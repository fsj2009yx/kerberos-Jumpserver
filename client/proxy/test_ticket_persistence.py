"""Tests for ticket persistence feature — run with: pytest test_ticket_persistence.py -v"""

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

# Ensure the proxy package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from krb.msg import ClientRuntime, ClientConfig, TicketBundle
from krb.ticket_store import MAGIC, save_tickets, load_tickets, delete_tickets


# ---------------------------------------------------------------------------
# Layer 1 — ticket_store 纯单元测试
# ---------------------------------------------------------------------------

class TestTicketStore:
    """save / load / delete / expiry 的独立测试，不依赖任何外部服务。"""

    @pytest.fixture
    def tmp_path_file(self, tmp_path):
        return str(tmp_path / "ticket.bin")

    @pytest.fixture
    def fresh_bundle(self):
        now = int(time.time())
        return TicketBundle(
            key_c_tgs=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            ticket_tgs=b"\xAA" * 64,
            key_c_v=b"\x11\x12\x13\x14\x15\x16\x17\x18",
            ticket_v=b"\xBB" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )

    # ---- save + load roundtrip ----

    def test_save_and_load_roundtrip(self, tmp_path_file, fresh_bundle):
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        assert os.path.isfile(tmp_path_file)

        bundle_dict, cid, sid = load_tickets(tmp_path_file)
        assert bundle_dict is not None
        assert cid == "CLIENT_1"
        assert sid == "verify_server"
        assert bundle_dict["key_c_v"] == fresh_bundle.key_c_v
        assert bundle_dict["ticket_v"] == fresh_bundle.ticket_v
        assert bundle_dict["tgt_expire"] == fresh_bundle.tgt_expire
        assert bundle_dict["tv_expire"] == fresh_bundle.tv_expire

    def test_save_writes_binary_blob(self, tmp_path_file, fresh_bundle):
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        raw = Path(tmp_path_file).read_bytes()

        assert raw.startswith(MAGIC)
        assert not raw.startswith(b"{")
        assert b"key_c_v" not in raw

    # ---- expired ticket ----

    def test_expired_ticket_returns_none_and_deletes_file(self, tmp_path_file, fresh_bundle):
        fresh_bundle.tv_expire = int(time.time()) - 1
        fresh_bundle.tgt_expire = int(time.time()) - 1
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        assert os.path.isfile(tmp_path_file)

        bundle_dict, cid, sid = load_tickets(tmp_path_file)
        assert bundle_dict is None
        assert cid is None
        assert not os.path.exists(tmp_path_file), "expired file should be deleted"

    def test_expired_ticket_v_keeps_valid_tgt(self, tmp_path_file, fresh_bundle):
        fresh_bundle.tv_expire = int(time.time()) - 1
        fresh_bundle.tgt_expire = int(time.time()) + 3600
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)

        bundle_dict, cid, sid = load_tickets(tmp_path_file)
        assert bundle_dict is not None
        assert cid == "CLIENT_1"
        assert sid == "verify_server"
        assert bundle_dict["key_c_tgs"] == fresh_bundle.key_c_tgs
        assert bundle_dict["ticket_tgs"] == fresh_bundle.ticket_tgs
        assert bundle_dict["key_c_v"] == b""
        assert bundle_dict["ticket_v"] == b""
        assert os.path.exists(tmp_path_file)

    # ---- missing file ----

    def test_load_missing_file_returns_none(self, tmp_path_file):
        bundle_dict, cid, sid = load_tickets(tmp_path_file)
        assert bundle_dict is None

    # ---- corrupted binary ----

    def test_corrupted_binary_returns_none(self, tmp_path_file):
        Path(tmp_path_file).parent.mkdir(parents=True, exist_ok=True)
        Path(tmp_path_file).write_bytes(b"not valid binary")
        bundle_dict, _, _ = load_tickets(tmp_path_file)
        assert bundle_dict is None

    # ---- truncated binary ----

    def test_truncated_binary_returns_none(self, tmp_path_file):
        Path(tmp_path_file).parent.mkdir(parents=True, exist_ok=True)
        Path(tmp_path_file).write_bytes(MAGIC + b"\x00\x08CLIENT")
        bundle_dict, _, _ = load_tickets(tmp_path_file)
        assert bundle_dict is None

    # ---- service ticket missing but TGT usable ----

    def test_empty_key_c_v_loads_valid_tgt(self, tmp_path_file, fresh_bundle):
        fresh_bundle.key_c_v = b""
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        bundle_dict, cid, sid = load_tickets(tmp_path_file)
        assert bundle_dict is not None
        assert cid == "CLIENT_1"
        assert sid == "verify_server"
        assert bundle_dict["key_c_tgs"] == fresh_bundle.key_c_tgs
        assert bundle_dict["key_c_v"] == b""

    # ---- delete ----

    def test_delete_removes_file(self, tmp_path_file, fresh_bundle):
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        assert os.path.isfile(tmp_path_file)
        delete_tickets(tmp_path_file)
        assert not os.path.exists(tmp_path_file)

    def test_delete_nonexistent_does_not_raise(self, tmp_path_file):
        delete_tickets(tmp_path_file)  # should not raise

    # ---- atomic write: tmp file cleaned up ----

    def test_save_does_not_leave_tmp_file(self, tmp_path_file, fresh_bundle):
        save_tickets(fresh_bundle, "CLIENT_1", "verify_server", tmp_path_file)
        assert not os.path.exists(tmp_path_file + ".tmp")


# ---------------------------------------------------------------------------
# Layer 2 — server.py 状态机 + login 决策逻辑（mock krb 调用 + mock fastapi）
# ---------------------------------------------------------------------------

def _inject_fastapi_mocks():
    """在 import api.server 之前，向 sys.modules 注入 fastapi 的假模块。

    FastAPI 的路由装饰器（@app.get / @app.post / @app.websocket）原样返回函数，
    确保测试中可以像普通 async 函数一样直接调用 login() / get_state() 等。
    """
    import types

    class _FakeFastAPI:
        """模拟 FastAPI 实例：装饰器原样返回函数，其他方法为 no-op。"""
        def __init__(self, *args, **kwargs):
            pass
        def get(self, _path):
            return lambda func: func
        def post(self, _path):
            return lambda func: func
        def websocket(self, _path):
            return lambda func: func
        def add_middleware(self, *args, **kwargs):
            pass

    class _FakeCORSMiddleware:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeStreamingResponse:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeWebSocketDisconnect(Exception):
        pass

    def _fake_form(default=mock.MagicMock()):
        return default

    # fastapi 顶层模块
    fastapi_mod = types.ModuleType("fastapi")
    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.WebSocket = object  # 仅用于类型注解
    fastapi_mod.WebSocketDisconnect = _FakeWebSocketDisconnect
    fastapi_mod.Form = _fake_form
    fastapi_mod.Query = _fake_form

    # fastapi.middleware.cors
    fastapi_cors = types.ModuleType("fastapi.middleware.cors")
    fastapi_cors.CORSMiddleware = _FakeCORSMiddleware

    # fastapi.middleware
    fastapi_middleware = types.ModuleType("fastapi.middleware")
    fastapi_middleware.cors = fastapi_cors

    # fastapi.responses
    fastapi_responses = types.ModuleType("fastapi.responses")
    fastapi_responses.StreamingResponse = _FakeStreamingResponse

    for name, mod in [
        ("fastapi", fastapi_mod),
        ("fastapi.middleware", fastapi_middleware),
        ("fastapi.middleware.cors", fastapi_cors),
        ("fastapi.responses", fastapi_responses),
    ]:
        sys.modules[name] = mod


_inject_fastapi_mocks()


class TestServerTicketLogic:
    """测试 server.py 中与票据缓存相关的决策逻辑，mock 所有网络调用。"""

    @pytest.fixture(autouse=True)
    def setup_server_module(self, monkeypatch):
        """每个测试前重置 server 模块的全局状态，并 mock krb 阶段函数。

        Mock 函数会像真实实现一样更新 runtime.state 和 runtime.bundle，
        确保 login() 的状态流转可以完整走通。
        """
        import api.server as server_mod

        now = int(time.time())

        def _fake_as(rt, cfg, username, password):
            rt.bundle.key_c_tgs = b"kctgs001"
            rt.bundle.ticket_tgs = b"TICKET_TGS" * 8
            rt.bundle.tgt_expire = now + 7200
            rt.state = "STATE_AS_DONE"
            return 0

        def _fake_tgs(rt, cfg, id_v):
            rt.bundle.key_c_v = b"kcv12345"
            rt.bundle.ticket_v = b"TICKET_V_" * 9
            rt.bundle.tv_expire = now + 3600
            rt.state = "STATE_TGS_DONE"
            return 0

        def _fake_ap(rt, cfg):
            rt.state = "STATE_V_CONNECTED"
            rt.v_sock = mock.MagicMock()
            return 0

        self.mock_as = mock.MagicMock(side_effect=_fake_as)
        self.mock_tgs = mock.MagicMock(side_effect=_fake_tgs)
        self.mock_ap = mock.MagicMock(side_effect=_fake_ap)

        monkeypatch.setattr(server_mod, "client_do_as", self.mock_as)
        monkeypatch.setattr(server_mod, "client_do_tgs", self.mock_tgs)
        monkeypatch.setattr(server_mod, "client_do_ap", self.mock_ap)

        # Reset global state
        server_mod.runtime = ClientRuntime()
        server_mod.config = ClientConfig(
            client_id="CLIENT_1",
            ad_c=0,
            as_addr=("127.0.0.1", 8881),
            tgs_addr=("127.0.0.1", 8882),
            v_addr=("127.0.0.1", 8883),
            cert_path="/fake/cert.json",
            privkey_path="/fake/key.json",
            service_id="verify_server",
            ticket_store_path="",
        )
        self.server_mod = server_mod
        return server_mod

    # ---- load persisted tickets ----

    def test_load_persisted_tickets_sets_state_tgs_done(
        self, setup_server_module, tmp_path
    ):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)

        mod._load_persisted_tickets()
        assert mod.runtime.state == "STATE_TGS_DONE"
        assert mod.runtime.bundle.key_c_v == b"v" * 8
        assert mod.runtime.bundle.ticket_v == b"s" * 80

    def test_load_ignores_expired_tickets(self, setup_server_module, tmp_path):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now - 1,
            tv_expire=now - 1,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)

        mod._load_persisted_tickets()
        assert mod.runtime.state == "STATE_INIT"
        assert mod.runtime.bundle.key_c_v == b""

    def test_load_expired_ticket_v_sets_state_as_done(
        self, setup_server_module, tmp_path
    ):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now - 1,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)

        mod._load_persisted_tickets()
        assert mod.runtime.state == "STATE_AS_DONE"
        assert mod.runtime.bundle.key_c_tgs == b"k" * 8
        assert mod.runtime.bundle.ticket_tgs == b"t" * 64
        assert mod.runtime.bundle.key_c_v == b""

    def test_load_mismatched_client_id_deletes_file(
        self, setup_server_module, tmp_path
    ):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_2", "verify_server", ticket_path)

        mod._load_persisted_tickets()
        assert mod.runtime.state == "STATE_INIT"
        assert not os.path.exists(ticket_path)

    # ---- login with cached tickets ----

    @pytest.mark.asyncio
    async def test_login_cached_skips_as_and_tgs(self, setup_server_module, tmp_path):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)
        mod._load_persisted_tickets()

        result = await mod.login(username="", password="")
        assert result["state"] == "STATE_V_CONNECTED"
        assert result.get("cached") is True
        # AS / TGS 不应被调用
        self.mock_as.assert_not_called()
        self.mock_tgs.assert_not_called()
        self.mock_ap.assert_called_once()

    @pytest.mark.asyncio
    async def test_login_cached_respects_explicit_password(
        self, setup_server_module, tmp_path
    ):
        """即使用户提供了密码，但缓存票据有效且用户名匹配时，优先走缓存。"""
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)
        mod._load_persisted_tickets()

        result = await mod.login(username="CLIENT_1", password="password")
        assert result["state"] == "STATE_V_CONNECTED"
        assert result.get("cached") is True
        self.mock_as.assert_not_called()
        self.mock_tgs.assert_not_called()

    @pytest.mark.asyncio
    async def test_logout_closes_live_v_socket_and_keeps_tickets(
        self, setup_server_module
    ):
        mod = setup_server_module
        now = int(time.time())
        sock = mock.MagicMock()
        mod.runtime.state = "STATE_V_CONNECTED"
        mod.runtime.v_sock = sock
        mod.runtime.session_id = "session-1"
        mod.runtime.bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )

        result = await mod.logout()

        assert result["closed_v_connection"] is True
        assert mod.runtime.v_sock is None
        assert mod.runtime.session_id is None
        assert mod.runtime.state == "STATE_TGS_DONE"
        assert mod.runtime.bundle.ticket_v == b"s" * 80
        sock.shutdown.assert_called_once()
        sock.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_login_with_valid_tgt_skips_as_without_password(
        self, setup_server_module, tmp_path
    ):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now - 1,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)
        mod._load_persisted_tickets()

        result = await mod.login(username="", password="")
        assert result["state"] == "STATE_V_CONNECTED"
        assert result.get("cached") is True
        self.mock_as.assert_not_called()
        self.mock_tgs.assert_called_once()
        self.mock_ap.assert_called_once()

    # ---- login without cached tickets ----

    @pytest.mark.asyncio
    async def test_login_no_cache_requires_password(self, setup_server_module):
        mod = setup_server_module

        result = await mod.login(username="CLIENT_1", password="")
        assert result.get("error") is not None
        assert "Password required" in result["error"]
        # 没有任何阶段被执行
        self.mock_as.assert_not_called()
        self.mock_tgs.assert_not_called()
        self.mock_ap.assert_not_called()

    @pytest.mark.asyncio
    async def test_login_no_cache_full_flow_with_password(
        self, setup_server_module
    ):
        mod = setup_server_module

        result = await mod.login(username="CLIENT_1", password="password")
        assert result["state"] == "STATE_V_CONNECTED"
        assert result.get("cached") is None  # no "cached" key for full flow
        # 三阶段全部执行
        self.mock_as.assert_called_once()
        self.mock_tgs.assert_called_once()
        self.mock_ap.assert_called_once()

    # ---- different user triggers full flow ----

    @pytest.mark.asyncio
    async def test_login_different_user_triggers_full_flow(
        self, setup_server_module, tmp_path
    ):
        """缓存的票据是 CLIENT_1，但登录请求是 CLIENT_2 → 应走完整流程。"""
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)
        mod._load_persisted_tickets()

        result = await mod.login(username="CLIENT_2", password="password2")
        assert result["state"] == "STATE_V_CONNECTED"
        # CLIENT_2 没有缓存，应走完整流程
        self.mock_as.assert_called_once()
        self.mock_tgs.assert_called_once()
        self.mock_ap.assert_called_once()

    # ---- save tickets after full login ----

    @pytest.mark.asyncio
    async def test_full_login_persists_tickets(self, setup_server_module, tmp_path):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        result = await mod.login(username="CLIENT_1", password="password")
        assert result["state"] == "STATE_V_CONNECTED"

        # 验证票据文件已写入
        assert os.path.isfile(ticket_path)
        bundle_dict, cid, sid = load_tickets(ticket_path)
        assert bundle_dict is not None
        assert cid == "CLIENT_1"
        assert sid == "verify_server"

    # ---- AP failure clears cached tickets ----

    @pytest.mark.asyncio
    async def test_cached_login_ap_failure_deletes_tickets(
        self, setup_server_module, tmp_path
    ):
        mod = setup_server_module
        ticket_path = str(tmp_path / "t.bin")
        mod.config.ticket_store_path = ticket_path

        now = int(time.time())
        bundle = TicketBundle(
            key_c_tgs=b"k" * 8,
            ticket_tgs=b"t" * 64,
            key_c_v=b"v" * 8,
            ticket_v=b"s" * 80,
            tgt_expire=now + 7200,
            tv_expire=now + 3600,
        )
        save_tickets(bundle, "CLIENT_1", "verify_server", ticket_path)
        mod._load_persisted_tickets()

        self.mock_ap.side_effect = lambda rt, cfg: -1

        result = await mod.login(username="", password="")
        assert "AP phase failed" in result.get("error", "")
        # 过期票据文件应被删除
        assert not os.path.exists(ticket_path)

    # ---- state API returns client_id ----

    @pytest.mark.asyncio
    async def test_state_api_returns_client_id(self, setup_server_module):
        mod = setup_server_module
        state = await mod.get_state()
        assert state["client_id"] == "CLIENT_1"
        assert "state" in state
        assert "tgt_expire" in state
        assert "tv_expire" in state
