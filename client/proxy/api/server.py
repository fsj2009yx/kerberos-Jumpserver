"""Client RESTful API服务器"""

import json
import hashlib
import asyncio
import contextlib
import socket
import sys
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import ClientRuntime, ClientConfig, TicketBundle
from krb.krb import client_do_as, client_do_tgs, client_do_ap, client_app_send_frame, client_app_recv_frame
from krb.ticket_store import save_tickets, load_tickets, delete_tickets
from debug.debug import log_error, log_info, log_warn


PTY_EVENT_OPEN_OK = 0x11
PTY_EVENT_OUTPUT = 0x12
PTY_EVENT_EXIT = 0x13
PTY_EVENT_ERROR = 0x14


# 全局状态
runtime = ClientRuntime()
config = None
pty_sessions: Dict[str, WebSocket] = {}
app_socket_lock = asyncio.Lock()


def _runtime_log(message: str, level: str = "info") -> None:
    runtime.logs.append(message)
    if level == "error":
        log_error(message)
    elif level == "warn":
        log_warn(message)
    else:
        log_info(message)


def _restore_ticket_state_after_disconnect():
    """Live V connection is gone; keep reusable cached tickets in memory."""
    now = int(time.time())
    if runtime.bundle.key_c_v and runtime.bundle.ticket_v and runtime.bundle.tv_expire > now:
        runtime.state = "STATE_TGS_DONE"
    elif runtime.bundle.key_c_tgs and runtime.bundle.ticket_tgs and runtime.bundle.tgt_expire > now:
        runtime.state = "STATE_AS_DONE"
    else:
        runtime.state = "STATE_INIT"


def _has_valid_service_ticket() -> bool:
    now = int(time.time())
    return bool(runtime.bundle.key_c_v and runtime.bundle.ticket_v and runtime.bundle.tv_expire > now)


def _open_v_app_connection(reason: str) -> bool:
    """Open a fresh APP/business TCP connection to V without repeating AP."""
    if runtime.state == "STATE_V_CONNECTED" and runtime.v_sock is not None:
        return True
    if not _has_valid_service_ticket():
        _runtime_log(f"Cannot open V APP connection during {reason}: no valid Ticket_V (state={runtime.state}).", "error")
        return False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(config.v_addr)
        runtime.v_sock = sock
        runtime.state = "STATE_V_CONNECTED"
        _runtime_log(f"Opened V APP connection for {reason}")
        return True
    except Exception as e:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        runtime.v_sock = None
        _restore_ticket_state_after_disconnect()
        _runtime_log(f"Cannot open V APP connection during {reason}: {type(e).__name__}: {e}", "error")
        return False


def _close_runtime_v_socket(reason: str) -> bool:
    """Close the live AP/APP TCP connection held by the Python proxy."""
    sock = runtime.v_sock
    runtime.v_sock = None
    runtime.session_id = None

    closed = False
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
            closed = True
        except Exception as e:
            _runtime_log(f"V connection close failed during {reason}: {e}", "error")

    _restore_ticket_state_after_disconnect()
    if closed:
        _runtime_log(f"V connection closed during {reason}; state={runtime.state}")
    return closed


async def _close_pty_websockets(reason: str):
    """Best-effort close of frontend PTY WebSocket sessions."""
    sessions = list(pty_sessions.items())
    pty_sessions.clear()
    for _, websocket in sessions:
        try:
            await websocket.close(code=1000, reason=reason)
        except Exception:
            pass
    return len(sessions)


async def _cleanup_live_client_session(reason: str, close_websockets: bool = False):
    closed_ws = 0
    if close_websockets:
        closed_ws = await _close_pty_websockets(reason)
    closed_socket = _close_runtime_v_socket(reason)
    return closed_socket, closed_ws


def init_config(config_path: str):
    """初始化配置"""
    global config
    config_path = os.path.abspath(config_path)
    config_dir = os.path.dirname(config_path)
    def resolve_path(path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.abspath(os.path.join(config_dir, path))

    with open(config_path, 'r') as f:
        cfg_data = json.load(f)
    if 'v_webui_host' not in cfg_data or 'v_webui_port' not in cfg_data:
        raise ValueError("client config must include v_webui_host and v_webui_port")
    config = ClientConfig(
        client_id=cfg_data['client_id'],
        ad_c=cfg_data['ad_c'],
        as_addr=(cfg_data['as_host'], cfg_data['as_port']),
        tgs_addr=(cfg_data['tgs_host'], cfg_data['tgs_port']),
        v_addr=(cfg_data['v_host'], cfg_data['v_port']),
        v_webui_addr=(cfg_data['v_webui_host'], int(cfg_data['v_webui_port'])),
        cert_path=resolve_path(cfg_data['cert_path']),
        privkey_path=resolve_path(cfg_data['privkey_path']),
        v_cert_path=resolve_path(cfg_data.get('v_cert_path', '../../certs/v_cert.json')),
        service_id=cfg_data.get('service_id', 'verify_server'),
        ticket_store_path=resolve_path(cfg_data.get('ticket_store_path', './tickets/ticket.bin')),
        target_catalog=cfg_data.get('target_catalog', []),
    )

    # 尝试从本地加载持久化票据
    _load_persisted_tickets()


def _load_persisted_tickets():
    """尝试从本地文件加载票据，恢复内存状态。"""
    global runtime
    if not config.ticket_store_path:
        return

    bundle_dict, client_id, service_id = load_tickets(config.ticket_store_path)
    if bundle_dict is None:
        return

    # 校验票据中的 client_id 与当前配置一致
    if client_id != config.client_id:
        delete_tickets(config.ticket_store_path)
        return

    # 校验 service_id 一致
    if service_id != config.service_id:
        delete_tickets(config.ticket_store_path)
        return

    # 恢复 TicketBundle 到内存
    runtime.bundle = TicketBundle(
        key_c_tgs=bundle_dict["key_c_tgs"],
        ticket_tgs=bundle_dict["ticket_tgs"],
        key_c_v=bundle_dict["key_c_v"],
        ticket_v=bundle_dict["ticket_v"],
        tgt_expire=bundle_dict["tgt_expire"],
        tv_expire=bundle_dict["tv_expire"],
    )

    # 判断票据阶段
    now = int(time.time())
    if runtime.bundle.key_c_v and runtime.bundle.ticket_v and runtime.bundle.tv_expire > now:
        runtime.state = "STATE_TGS_DONE"
        runtime.logs.append(f"Tickets loaded from {config.ticket_store_path} "
                            f"(tv_expire={runtime.bundle.tv_expire}, "
                            f"tgt_expire={runtime.bundle.tgt_expire})")
    elif runtime.bundle.key_c_tgs and runtime.bundle.ticket_tgs and runtime.bundle.tgt_expire > now:
        runtime.state = "STATE_AS_DONE"
        runtime.logs.append(f"TGT loaded from {config.ticket_store_path} "
                            f"(tgt_expire={runtime.bundle.tgt_expire})")
    else:
        # 票据过期或数据不完整，清除
        runtime.bundle = TicketBundle()
        delete_tickets(config.ticket_store_path)


app = FastAPI(title="Kerberos Client API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """根路径 - 返回API文档"""
    return {
        "title": "Kerberos Client API",
        "version": "1.0",
        "endpoints": {
            "POST /api/login": "Kerberos三阶段认证登录",
            "GET /api/state": "获取客户端状态",
            "GET /api/targets": "获取SSH目标列表",
            "GET /api/cert": "获取客户端证书",
            "GET /api/logs": "SSE实时日志流",
            "WS /ws/pty": "PTY终端会话"
        },
        "login_example": {
            "username": "CLIENT_1",
            "password": "password"
        }
    }


@app.post("/api/login")
async def login(username: str = Form(""), password: str = Form("")):
    """触发Kerberos三阶段认证。

    如果本地有未过期的有效票据，自动跳过 AS/TGS 阶段，仅执行 AP 连接。
    """
    global runtime

    # 关闭已有 V 连接，避免重新登录时遗留旧 AP/APP 长连接。
    await _cleanup_live_client_session("login restart", close_websockets=True)

    now = int(time.time())

    # —— 判断是否可以跳过 AS / TGS 阶段 ——
    can_skip_as = False
    can_skip_tgs = False
    effective_username = username.strip() if username.strip() else config.client_id

    if runtime.state == "STATE_TGS_DONE" and runtime.bundle.tv_expire > now:
        if runtime.bundle.key_c_v and runtime.bundle.ticket_v:
            if not username.strip() or username.strip() == config.client_id:
                can_skip_as = True
                can_skip_tgs = True
    elif runtime.state == "STATE_AS_DONE" and runtime.bundle.tgt_expire > now:
        if runtime.bundle.key_c_tgs and runtime.bundle.ticket_tgs:
            if not username.strip() or username.strip() == config.client_id:
                can_skip_as = True

    # 如果需要全流程但未提供密码，返回错误
    if not can_skip_as and not password:
        return {
            "state": runtime.state,
            "error": "No valid tickets found. Password required for full authentication."
        }

    # —— 执行认证 ——
    if can_skip_tgs:
        # 票据完整有效，仅执行 AP 阶段
        config.client_id = effective_username
        # 保留已加载的 bundle，不重置 runtime
        runtime.state = "STATE_TGS_DONE"
        runtime.logs.append(f"Login (cached): skipping AS/TGS, running AP for {effective_username}")

        result = client_do_ap(runtime, config)
        if result != 0:
            # AP 失败（可能是 V 端票据过期或 V 不可达），清除过期票据
            delete_tickets(config.ticket_store_path)
            runtime.bundle.tv_expire = 0
            return {"state": runtime.state, "error": "AP phase failed — tickets may have been revoked"}

        runtime.logs.append(f"Login completed (cached) for {effective_username}")
        _persist_after_login()
        import uuid
        login_session_id = str(uuid.uuid4())
        runtime.session_id = login_session_id
        login_state = runtime.state
        _close_runtime_v_socket("login AP probe complete")
        return {
            "state": login_state,
            "tgt_expire": runtime.bundle.tgt_expire,
            "tv_expire": runtime.bundle.tv_expire,
            "session_id": login_session_id,
            "cached": True,
        }

    if can_skip_as:
        # TGT 有效、但服务票据缺失或过期，执行 TGS + AP
        config.client_id = effective_username
        runtime.state = "STATE_AS_DONE"
        runtime.logs.append(f"Login (partial cache): skipping AS, running TGS+AP for {effective_username}")

        result = client_do_tgs(runtime, config, config.service_id)
        if result != 0:
            delete_tickets(config.ticket_store_path)
            return {"state": runtime.state, "error": "TGS phase failed"}

        result = client_do_ap(runtime, config)
        if result != 0:
            return {"state": runtime.state, "error": "AP phase failed"}

        runtime.logs.append(f"Login completed (partial cache) for {effective_username}")
        _persist_after_login()
        import uuid
        login_session_id = str(uuid.uuid4())
        runtime.session_id = login_session_id
        login_state = runtime.state
        _close_runtime_v_socket("login AP probe complete")
        return {
            "state": login_state,
            "tgt_expire": runtime.bundle.tgt_expire,
            "tv_expire": runtime.bundle.tv_expire,
            "session_id": login_session_id,
            "cached": True,
        }

    # —— 完整三阶段认证 ——
    runtime = ClientRuntime()
    config.client_id = effective_username
    runtime.logs.append(f"Login started for {effective_username}")

    # AS阶段
    result = client_do_as(runtime, config, effective_username, password)
    if result != 0:
        return {"state": runtime.state, "error": "AS phase failed"}

    # TGS阶段
    result = client_do_tgs(runtime, config, config.service_id)
    if result != 0:
        return {"state": runtime.state, "error": "TGS phase failed"}

    # AP阶段
    result = client_do_ap(runtime, config)
    if result != 0:
        return {"state": runtime.state, "error": "AP phase failed"}

    runtime.logs.append(f"Login completed for {effective_username}")
    _persist_after_login()

    import uuid
    login_session_id = str(uuid.uuid4())
    runtime.session_id = login_session_id
    login_state = runtime.state
    _close_runtime_v_socket("login AP probe complete")

    return {
        "state": login_state,
        "tgt_expire": runtime.bundle.tgt_expire,
        "tv_expire": runtime.bundle.tv_expire,
        "session_id": login_session_id
    }
print(f"[DEBUG] runtime.logs count: {len(runtime.logs)}")
print(f"[DEBUG] PacketLog count: {sum(1 for x in runtime.logs if hasattr(x, 'to_dict'))}")


@app.post("/api/logout")
async def logout():
    """Close live frontend/backend sessions without deleting persisted tickets."""
    closed_socket, closed_ws = await _cleanup_live_client_session("logout", close_websockets=True)
    return {
        "state": runtime.state,
        "closed_v_connection": closed_socket,
        "closed_pty_websockets": closed_ws,
    }


def _persist_after_login():
    """登录成功后持久化票据到本地文件。"""
    if not config.ticket_store_path:
        return
    try:
        save_tickets(runtime.bundle, config.client_id, config.service_id, config.ticket_store_path)
        runtime.logs.append(f"Tickets saved to {config.ticket_store_path}")
    except Exception as e:
        runtime.logs.append(f"Failed to save tickets: {e}")


@app.get("/api/state")
async def get_state():
    """获取当前Client状态"""
    return {
        "state": runtime.state,
        "client_id": config.client_id,
        "k_ctgs_sha256": hashlib.sha256(runtime.bundle.key_c_tgs).hexdigest() if runtime.bundle.key_c_tgs else "",
        "k_cv_sha256": hashlib.sha256(runtime.bundle.key_c_v).hexdigest() if runtime.bundle.key_c_v else "",
        "tgt_expire": runtime.bundle.tgt_expire,
        "tv_expire": runtime.bundle.tv_expire,
        "seq_num": runtime.seq_num
    }


@app.get("/api/targets")
async def get_targets():
    """认证后从 V 拉取 SSH 目标列表；权威 SSH 配置只在 V 端。"""
    if runtime.state not in ("STATE_V_CONNECTED", "STATE_TGS_DONE") or not _has_valid_service_ticket():
        return {"targets": [], "error": f"client has no valid V ticket (state={runtime.state})"}

    def fetch_from_v():
        if config.v_webui_addr is None:
            raise RuntimeError("v_webui_addr is not configured")
        host, port = config.v_webui_addr
        url = f"http://{host}:{port}/api/targets"
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))

    try:
        data = await asyncio.to_thread(fetch_from_v)
    except (OSError, urllib.error.URLError, TimeoutError) as e:
        return {"targets": [], "error": f"failed to fetch targets from V: {e}"}

    targets = []
    for target in data.get("targets", []):
        allowed = target.get("allowed_clients", [])
        if allowed and config.client_id not in allowed:
            continue
        targets.append({
            "id": target.get("id", ""),
            "host": target.get("host", ""),
            "port": target.get("port", 22),
            "ssh_user": target.get("ssh_user", ""),
        })
    return {"targets": targets}


@app.get("/api/cert")
async def get_cert():
    """获取Client证书"""
    with open(config.cert_path, 'r') as f:
        cert = json.load(f)
    return cert


@app.get("/api/logs")
async def get_logs():
    """SSE实时日志流 - 通信封包记录(实时回传 WEBUI)"""
    async def log_stream():
        last_index = 0
        while True:
            # 检查是否有新日志
            while last_index < len(runtime.logs):
                log_entry = runtime.logs[last_index]
                last_index += 1
                
                # 检查是否是 PacketLog 对象（新格式）
                if hasattr(log_entry, 'to_dict'):
                    # 按照设计文档格式输出完整的数据包信息
                    packet_dict = log_entry.to_dict()
                    yield f"data: {json.dumps(packet_dict)}\n\n"
                else:
                    # 旧格式的日志字符串
                    yield f"data: {json.dumps({'message': log_entry})}\n\n"
            
            await asyncio.sleep(0.1)
    return StreamingResponse(log_stream(), media_type="text/event-stream")


import base64

async def send_pty_event(websocket: WebSocket, event):
    """把V服务器的APP_REP事件转成前端WebSocket事件。"""
    session_id = str(event.pty_session_id)
    if event.pty_event == PTY_EVENT_OPEN_OK:
        await websocket.send_json({
            'event': 'open_ok',
            'session_id': session_id
        })
    elif event.pty_event == PTY_EVENT_OUTPUT:
        # 按照设计文档：Client -> Web 的 data 字段需要 base64 编码
        await websocket.send_json({
            'event': 'output',
            'session_id': session_id,
            'data': base64.b64encode(event.payload).decode('utf-8')
        })
    elif event.pty_event == PTY_EVENT_EXIT:
        await websocket.send_json({
            'event': 'exit',
            'session_id': session_id,
            'exit_code': event.exit_code
        })
    elif event.pty_event == PTY_EVENT_ERROR:
        # 按照设计文档：error 的 data 字段需要 base64 编码
        await websocket.send_json({
            'event': 'error',
            'session_id': session_id,
            'data': base64.b64encode(event.payload).decode('utf-8')
        })


async def forward_incidental_events(websocket: WebSocket, events):
    for event in events:
        await send_pty_event(websocket, event)


async def drain_available_pty_events(websocket: WebSocket, max_frames: int = 8):
    for _ in range(max_frames):
        async with app_socket_lock:
            event = client_app_recv_frame(runtime, config, timeout=0.05)
        if event is None:
            return
        await send_pty_event(websocket, event)


async def pty_output_pump(websocket: WebSocket, session_id_ref: Dict[str, Optional[str]]):
    """Continuously drain PTY output for an active session."""
    try:
        while True:
            if not session_id_ref.get("session_id"):
                await asyncio.sleep(0.05)
                continue
            await drain_available_pty_events(websocket)
            await asyncio.sleep(0.02)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        message = f"PTY output pump failed: {type(e).__name__}: {e}"
        _runtime_log(message, "error")
        with contextlib.suppress(Exception):
            await websocket.send_json({"event": "error", "message": message})


async def send_app_frame_locked(pty_op: int, session_id: int, payload: bytes,
                                expected_events: set[int], incidental_events: list):
    async with app_socket_lock:
        return client_app_send_frame(
            runtime,
            config,
            pty_op,
            session_id,
            payload,
            expected_events,
            incidental_events,
        )


@app.websocket("/ws/pty")
async def websocket_pty(websocket: WebSocket):
    """PTY长连接会话"""
    await websocket.accept()
    _runtime_log("PTY websocket accepted")

    session_id = None
    session_id_ref: Dict[str, Optional[str]] = {"session_id": None}
    output_task = asyncio.create_task(pty_output_pump(websocket, session_id_ref))
    close_live_connection = False
    try:
        while True:
            data = await websocket.receive_json()
            op = data.get('op', '')
            
            if op == 'open':
                # 打开新会话
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                term = data.get('term', 'xterm')
                target_id = (data.get('target_id') or '').strip()

                if not target_id:
                    message = 'PTY open failed: target_id is required.'
                    _runtime_log(message, "error")
                    await websocket.send_json({'event': 'error', 'message': message})
                    continue

                if not _open_v_app_connection(f"pty target={target_id}"):
                    message = f'PTY open failed: could not connect to V APP service (state={runtime.state}).'
                    _runtime_log(message, "error")
                    await websocket.send_json({'event': 'error', 'message': message})
                    continue
                
                term_raw = term.encode()
                if target_id:
                    target_raw = target_id.encode()
                    payload = (
                        len(target_raw).to_bytes(2, 'big') + target_raw +
                        len(term_raw).to_bytes(2, 'big') + term_raw +
                        cols.to_bytes(2, 'big') + rows.to_bytes(2, 'big')
                    )
                    pty_op = 0x06
                else:
                    payload = len(term_raw).to_bytes(2, 'big') + term_raw + cols.to_bytes(2, 'big') + rows.to_bytes(2, 'big')
                    pty_op = 0x01
                
                incidental = []
                result = await send_app_frame_locked(pty_op, 0, payload, {PTY_EVENT_OPEN_OK, PTY_EVENT_ERROR}, incidental)
                if result:
                    session_id = str(result.pty_session_id)
                    session_id_ref["session_id"] = session_id
                    pty_sessions[session_id] = websocket
                    await forward_incidental_events(websocket, incidental)
                    await send_pty_event(websocket, result)
                else:
                    await forward_incidental_events(websocket, incidental)
                    message = f"PTY open failed: no response from V server (state={runtime.state}, seq={runtime.seq_num})."
                    _runtime_log(message, "error")
                    await websocket.send_json({'event': 'error', 'message': message})
            
            elif op == 'input':
                # 输入数据 - 按照设计文档：Web -> Client 的 data 字段是 base64 编码
                session_id = data.get('session_id')
                input_data = data.get('data', '')
                
                if session_id and input_data:
                    # base64 解码
                    payload = base64.b64decode(input_data)
                    incidental = []
                    result = await send_app_frame_locked(0x02, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
            
            elif op == 'resize':
                # 窗口调整
                session_id = data.get('session_id')
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                
                if session_id:
                    payload = cols.to_bytes(2, 'big') + rows.to_bytes(2, 'big')
                    incidental = []
                    result = await send_app_frame_locked(0x03, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
            
            elif op == 'signal':
                # 发送信号
                session_id = data.get('session_id')
                signal = data.get('signal', 'INT')
                
                if session_id:
                    signal_map = {'INT': 1, 'TERM': 2, 'KILL': 3}
                    sig_num = signal_map.get(signal, 1)
                    payload = sig_num.to_bytes(1, 'big')
                    incidental = []
                    result = await send_app_frame_locked(0x04, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
            
            elif op == 'close':
                # 关闭会话
                session_id = data.get('session_id')
                
                if session_id:
                    incidental = []
                    result = await send_app_frame_locked(0x05, int(session_id), b'', {PTY_EVENT_EXIT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
                    if session_id in pty_sessions:
                        del pty_sessions[session_id]
                    session_id_ref["session_id"] = None
                    _close_runtime_v_socket("pty close")
                    break
    
    except WebSocketDisconnect:
        _runtime_log(f"PTY websocket disconnected session={session_id}")
        close_live_connection = True
        if session_id and session_id in pty_sessions:
            del pty_sessions[session_id]
            session_id_ref["session_id"] = None
    except Exception as e:
        _runtime_log(f"PTY websocket failed session={session_id}: {type(e).__name__}: {e}", "error")
        close_live_connection = True
        if session_id and session_id in pty_sessions:
            del pty_sessions[session_id]
            session_id_ref["session_id"] = None
        try:
            await websocket.send_json({
                'event': 'error',
                'message': str(e)
            })
        except Exception:
            pass
    finally:
        if output_task:
            output_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await output_task
        if session_id and session_id in pty_sessions:
            del pty_sessions[session_id]
        if close_live_connection:
            _close_runtime_v_socket("pty websocket disconnect")
