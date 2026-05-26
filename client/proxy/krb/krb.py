"""Kerberos客户端核心逻辑"""

import socket
import time
import json
import sys
import os
import base64
from typing import Optional

# 添加当前目录到路径，支持直接运行
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import *
from krb.logger import (
    PTY_EVENT_NAMES,
    PTY_OP_NAMES,
    decrypt_payload,
    log_packet as krb_log_packet,
)
from crypto.des import encrypt_des_cbc, decrypt_des_cbc
from crypto.sha256 import sha256
from crypto.rsa import rsa_sign, rsa_verify

# 导入调试模块
try:
    from debug.debug import (
        log_info, log_debug, log_error, log_packet, log_state_change,
        log_encryption, log_decryption, hexdump, validate_packet_structure
    )
except ImportError:
    # 如果调试模块不存在，定义空函数
    def log_info(*args, **kwargs): pass
    def log_debug(*args, **kwargs): pass
    def log_error(*args, **kwargs): pass
    def log_packet(*args, **kwargs): pass
    def log_state_change(*args, **kwargs): pass
    def log_encryption(*args, **kwargs): pass
    def log_decryption(*args, **kwargs): pass
    def hexdump(*args, **kwargs): pass
    def validate_packet_structure(*args, **kwargs): return True


# 错误码定义
KRB_OK = 0
ERR_MAGIC_MISMATCH = -1001
ERR_VERSION_UNSUPPORTED = -1002
ERR_MSG_TYPE_INVALID = -1003
ERR_PAYLOAD_TOO_LARGE = -1004
ERR_REPLAY_TIMESTAMP = -1005
ERR_REPLAY_SEQ = -1006
ERR_BUF_TOO_SMALL = -1007
ERR_SOCKET_SEND = -1008
ERR_SOCKET_RECV = -1009

ERR_CLIENT_NOT_FOUND = -2001
ERR_TICKET_EXPIRED = -2002
ERR_TICKET_INVALID = -2003
ERR_AUTH_MISMATCH = -2004
ERR_AD_MISMATCH = -2005
ERR_KEY_DERIVE = -2006
ERR_SESSION_NOT_FOUND = -2007

ERR_DES_KEY_LEN = -3001
ERR_DES_PADDING = -3002
ERR_DES_DECRYPT_FAIL = -3003
ERR_RSA_KEY_INVALID = -3004
ERR_RSA_SIGN_FAIL = -3005
ERR_RSA_VERIFY_FAIL = -3006


def krb_pack(msg_type: int, seq_num: int, timestamp: int, payload: bytes) -> bytes:
    """封包函数：添加Kerberos协议首部"""
    header = KerHeader(
        magic=0x4B45,
        version=0x01,
        msg_type=msg_type,
        total_len=len(payload),
        seq_num=seq_num,
        timestamp=timestamp,
        addition=0
    )
    return header.to_bytes() + payload


def krb_unpack(raw: bytes) -> tuple[KerHeader, bytes]:
    """拆包函数：解析协议首部和Payload"""
    if len(raw) < 20:
        raise ValueError("Buffer too short")
    
    header = KerHeader.from_bytes(raw[:20])
    
    # 验证Magic Number
    if header.magic != 0x4B45:
        raise ValueError(f"Magic mismatch: {header.magic}")
    
    # 验证版本
    if header.version != 0x01:
        raise ValueError(f"Unsupported version: {header.version}")
    
    # 验证消息类型
    if header.msg_type not in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff]:
        raise ValueError(f"Invalid message type: {header.msg_type}")
    
    # 获取Payload
    payload = raw[20:20+header.total_len]
    
    return header, payload


def krb_recv_full(sock: socket.socket, need: int) -> bytes:
    """保证完整接收指定字节数"""
    received = b""
    while len(received) < need:
        chunk = sock.recv(need - len(received))
        if not chunk:
            raise ConnectionError("Socket closed")
        received += chunk
    return received


def _socket_host(sock: socket.socket, endpoint: str, fallback: str = "unknown") -> str:
    """从已连接socket读取本端或对端IP，用于日志和包方向标记。"""
    try:
        addr = sock.getsockname() if endpoint == "local" else sock.getpeername()
    except Exception:
        return fallback
    if isinstance(addr, tuple) and addr:
        return str(addr[0])
    return str(addr) if addr else fallback


def _connected_hosts(sock: socket.socket, peer_fallback: str = "unknown") -> tuple[str, str]:
    """返回当前TCP连接的本端IP和对端IP。"""
    return _socket_host(sock, "local"), _socket_host(sock, "peer", peer_fallback)


def send_packet(sock: socket.socket, msg_type: int, seq_num: int, payload: bytes, 
                runtime=None, src_addr=None, dst_addr=None) -> bytes:
    """发送一个Kerberos协议包"""
    # 从socket获取地址，如果没有提供的话
    if src_addr is None:
        src_addr = _socket_host(sock, "local")
    if dst_addr is None:
        dst_addr = _socket_host(sock, "peer")
    
    timestamp = int(time.time())
    packet = krb_pack(msg_type, seq_num, timestamp, payload)
    
    # 添加调试日志
    log_info(f"Sending packet - MsgType: 0x{msg_type:02X}, SeqNum: {seq_num}, PayloadLen: {len(payload)}")
    log_packet({
        'magic': 0x4B45,
        'version': 0x01,
        'msg_type': msg_type,
        'total_len': len(payload),
        'seq_num': seq_num,
        'timestamp': timestamp
    }, payload)
    
    # 使用新的日志格式记录完整数据包
    
    
    sock.sendall(packet)
    return packet


def recv_packet(sock: socket.socket, runtime=None, src_addr=None, dst_addr=None) -> tuple[KerHeader, bytes]:
    """接收一个Kerberos协议包"""
    # 从socket获取地址，如果没有提供的话
    if src_addr is None:
        src_addr = _socket_host(sock, "peer")
    if dst_addr is None:
        dst_addr = _socket_host(sock, "local")
    
    header_raw = krb_recv_full(sock, 20)
    log_debug(f"Received header: {header_raw.hex()}")
    
    header = KerHeader.from_bytes(header_raw)
    
    # 添加调试日志
    log_info(f"Received packet - MsgType: 0x{header.msg_type:02X}, SeqNum: {header.seq_num}, PayloadLen: {header.total_len}")
    
    if header.magic != 0x4B45:
        log_error(f"Response magic mismatch: expected 0x4B45, got 0x{header.magic:04X}")
        raise ValueError("Response magic mismatch")

    if header.msg_type == 0xff:
        error_data = krb_recv_full(sock, header.total_len)
        error_code = int.from_bytes(error_data, 'big', signed=True)
        log_error(f"Server error code: {error_code}")
        raise RuntimeError(f"Server error: {error_code}")

    payload_raw = krb_recv_full(sock, header.total_len)
    
    # 记录完整数据包信息
    log_packet({
        'magic': header.magic,
        'version': header.version,
        'msg_type': header.msg_type,
        'total_len': header.total_len,
        'seq_num': header.seq_num,
        'timestamp': header.timestamp
    }, payload_raw)
    
    # 使用新的日志格式记录完整数据包
    
    
    return header, payload_raw


def send_recv_packet(sock: socket.socket, msg_type: int, seq_num: int,
                     payload: bytes, runtime=None, src_addr=None, dst_addr=None) -> tuple[KerHeader, bytes]:
    """发送请求并接收响应"""
    send_packet(sock, msg_type, seq_num, payload, runtime, src_addr, dst_addr)
    return recv_packet(sock, runtime, dst_addr, src_addr)


def pack_as_req(id_client: str, id_tgs: str, ts1: int) -> bytes:
    """编码AS_REQ Payload"""
    payload = ASReqPayload(
        id_client=KString(length=len(id_client), data=id_client.encode()),
        id_tgs=KString(length=len(id_tgs), data=id_tgs.encode()),
        ts1=ts1
    )
    return payload.to_bytes()


def unpack_as_rep(payload: bytes, kc: bytes) -> ASRepPlain:
    """解包并解密AS_REP"""
    wire = ASRepPayloadWire.from_bytes(payload)
    plain_data = decrypt_des_cbc(kc, wire.enc_part)
    return ASRepPlain.from_bytes(plain_data)


def pack_tgs_req(id_v: str, ticket_tgs: bytes, key_c_tgs: bytes, 
                 id_client: str, ad_c: int, ts3: int) -> bytes:
    """编码TGS_REQ（含加密Authenticator_c）"""
    # 构造Authenticator
    auth_plain = AuthenticatorPlain(
        id_client=KString(length=len(id_client), data=id_client.encode()),
        ad_c=ad_c,
        ts=ts3
    )
    auth_cipher = encrypt_des_cbc(key_c_tgs, auth_plain.to_bytes())
    
    payload = TGSReqPayload(
        id_v=KString(length=len(id_v), data=id_v.encode()),
        ticket_len=len(ticket_tgs),
        ticket_tgs=ticket_tgs,
        auth_len=len(auth_cipher),
        authenticator_c=auth_cipher
    )
    return payload.to_bytes()


def unpack_tgs_rep(payload: bytes, key_c_tgs: bytes) -> TGSRepPlain:
    """解包并解密TGS_REP"""
    wire = TGSRepPayloadWire.from_bytes(payload)
    plain_data = decrypt_des_cbc(key_c_tgs, wire.enc_part)
    return TGSRepPlain.from_bytes(plain_data)


def pack_ap_req(ticket_v: bytes, key_c_v: bytes, id_client: str, ad_c: int, ts5: int) -> bytes:
    """编码AP_REQ"""
    # 构造Authenticator
    auth_plain = AuthenticatorPlain(
        id_client=KString(length=len(id_client), data=id_client.encode()),
        ad_c=ad_c,
        ts=ts5
    )
    auth_cipher = encrypt_des_cbc(key_c_v, auth_plain.to_bytes())
    
    payload = APReqPayload(
        ticket_v_len=len(ticket_v),
        ticket_v=ticket_v,
        auth_len=len(auth_cipher),
        authenticator_c=auth_cipher
    )
    return payload.to_bytes()


def verify_ap_rep(payload: bytes, key_c_v: bytes, ts5: int) -> int:
    """验证AP_REP中的TS5+1"""
    wire = APRepPayloadWire.from_bytes(payload)
    plain_data = decrypt_des_cbc(key_c_v, wire.enc_part)
    ap_rep = APRepPlain.from_bytes(plain_data)
    
    if ap_rep.ts5_plus_1 != ts5 + 1:
        raise ValueError("AP_REP TS verification failed")
    
    return ap_rep.ts5_plus_1


def pack_app_req(id_client: str, key_c_v: bytes, pty_op: int,
                 pty_session_id: int, payload: bytes, priv_key: dict,
                 seq_num: int) -> bytes:
    """编码APP_REQ并追加RSA签名"""
    # 构造APP_REQ内层明文
    app_plain = APPReqPlain(
        pty_op=pty_op,
        pty_session_id=pty_session_id,
        payload_len=len(payload),
        payload=payload
    )
    
    # DES加密
    cipher_data = encrypt_des_cbc(key_c_v, app_plain.to_bytes())
    
    # V 端验签内容是协议头 seq_num + APP_REQ 密文。
    sign_data = seq_num.to_bytes(4, 'big') + cipher_data
    msg_hash = sha256(sign_data)
    
    # RSA签名
    signature = rsa_sign(msg_hash, priv_key)
    
    # 构造外层Payload
    id_client_kstr = KString(length=len(id_client), data=id_client.encode())
    app_req = APPReqPayload(
        id_client=id_client_kstr,
        cipher_len=len(cipher_data),
        cipher_data=cipher_data,
        rsa_sign_c=signature
    )
    
    return app_req.to_bytes()


def _cert_body_bytes(cert: dict) -> bytes:
    body = {
        "id": cert.get("id", ""),
        "issuer": cert.get("issuer", ""),
        "public_key": {
            "n": cert.get("public_key", {}).get("n", ""),
            "e": cert.get("public_key", {}).get("e", ""),
        },
        "expire": cert.get("expire", ""),
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _decode_cert_signature(value: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise ValueError("empty certificate signature")
    if len(value) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in value):
        return bytes.fromhex(value)
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return bytes.fromhex(value)


def verify_certificate(cert: dict, expected_id: str) -> dict:
    """验证项目自定义证书，并返回证书中的RSA公钥。"""
    if cert.get("id") != expected_id:
        raise ValueError(f"certificate id mismatch: {cert.get('id')} != {expected_id}")
    expire = cert.get("expire", "")
    try:
        expire_ts = int(time.mktime(time.strptime(expire + " 23:59:59", "%Y-%m-%d %H:%M:%S")))
    except Exception as exc:
        raise ValueError("certificate expire is invalid") from exc
    if int(time.time()) > expire_ts:
        raise ValueError("certificate has expired")
    pub_key = cert.get("public_key")
    if not isinstance(pub_key, dict) or not pub_key.get("n") or not pub_key.get("e"):
        raise ValueError("certificate public key is invalid")
    sig = _decode_cert_signature(cert.get("sign", ""))
    if not rsa_verify(sha256(_cert_body_bytes(cert)), sig, pub_key):
        raise ValueError("certificate signature is invalid")
    return pub_key


def load_verified_v_public_key(cfg: ClientConfig) -> dict:
    if not cfg.v_cert_path:
        raise ValueError("v_cert_path is not configured")
    with open(cfg.v_cert_path, "r", encoding="utf-8") as f:
        cert = json.load(f)
    return verify_certificate(cert, cfg.service_id)


def unpack_app_rep(payload: bytes, key_c_v: bytes, seq_num: int, v_pub_key: dict) -> APPRepPlain:
    """解包APP_REP：先验V签名，再解密。"""
    app_rep = APPRepPayload.from_bytes(payload)
    sign_data = seq_num.to_bytes(4, 'big') + app_rep.cipher_data
    if not rsa_verify(sha256(sign_data), app_rep.rsa_sign_v, v_pub_key):
        raise ValueError("APP_REP signature verification failed")
    plain_data = decrypt_des_cbc(key_c_v, app_rep.cipher_data)
    return APPRepPlain.from_bytes(plain_data)


def _signature_status(required: bool, verified: Optional[bool], signer: str,
                      verifier: str, detail: str) -> dict:
    if not required:
        status = "not_required"
    elif verified is True:
        status = "verified"
    elif verified is False:
        status = "failed"
    else:
        status = "pending"
    return {
        "required": required,
        "verified": verified,
        "status": status,
        "algorithm": "RSA-SHA256",
        "signer": signer,
        "verifier": verifier,
        "detail": detail,
    }


def _app_req_info(pty_op: int, pty_session_id: int, payload_len: int) -> str:
    op_name = PTY_OP_NAMES.get(pty_op, f"0x{pty_op:02x}")
    return f"APP_REQ decrypted - {op_name} session={pty_session_id} payload={payload_len} bytes"


def _app_rep_info(rep: APPRepPlain) -> str:
    event_name = PTY_EVENT_NAMES.get(rep.pty_event, f"0x{rep.pty_event:02x}")
    return f"APP_REP decrypted - {event_name} session={rep.pty_session_id} payload={rep.payload_len} bytes"


def _app_rep_failed_signature_info(resp_payload: bytes) -> str:
    try:
        app_rep = APPRepPayload.from_bytes(resp_payload)
        return f"APP_REP signature failed - cipher={len(app_rep.cipher_data)} bytes"
    except Exception:
        return "APP_REP signature failed"


def client_app_recv_frame(rt: ClientRuntime, cfg: ClientConfig, timeout: Optional[float] = None) -> Optional[APPRepPlain]:
    """从已认证的V连接上读取一个APP响应帧。timeout到期时返回None。"""
    sock = rt.v_sock
    if sock is None:
        msg = "V session is not connected"
        log_error(msg)
        raise RuntimeError(msg)

    old_timeout = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        header, resp_payload = recv_packet(sock)
    except socket.timeout:
        return None
    finally:
        if timeout is not None:
            sock.settimeout(old_timeout)

    if header.msg_type != 0x07:
        msg = f"Unexpected APP response type: {header.msg_type}"
        log_error(msg)
        raise RuntimeError(msg)
    try:
        v_pub_key = load_verified_v_public_key(cfg)
        local_host, peer_host = _connected_hosts(sock, cfg.v_addr[0])
        full_packet = header.to_bytes() + resp_payload
        try:
            app_rep = unpack_app_rep(resp_payload, rt.bundle.key_c_v, header.seq_num, v_pub_key)
        except Exception:
            krb_log_packet(
                rt,
                peer_host,
                local_host,
                "APP",
                _app_rep_failed_signature_info(resp_payload),
                full_packet,
                [
                    "  APP_Direction: APP_REP",
                    "  Signature_Required: yes",
                    "  Signature_Verified: no",
                    "  Verify_Status: failed",
                    f"  Payload(hex): {resp_payload.hex()}",
                ],
                _signature_status(
                    True,
                    False,
                    cfg.service_id,
                    cfg.client_id,
                    "APP_REP RSA signature verification failed; plaintext was not trusted.",
                ),
            )
            raise

        decoded_lines = decrypt_payload(0x07, resp_payload, rt.bundle.key_c_v)
        krb_log_packet(
            rt,
            peer_host,
            local_host,
            "APP",
            _app_rep_info(app_rep),
            full_packet,
            decoded_lines,
            _signature_status(
                True,
                True,
                cfg.service_id,
                cfg.client_id,
                "APP_REP RSA signature verified before DES-CBC plaintext was accepted.",
            ),
        )
        return app_rep
    except Exception as e:
        log_error(f"APP response verification/decrypt failed: {type(e).__name__}: {e}")
        try:
            sock.close()
        except Exception:
            pass
        rt.v_sock = None
        rt.state = "STATE_ERROR"
        raise


def client_do_as(rt: ClientRuntime, cfg: ClientConfig, username: str, password: str) -> int:
    """AS阶段编排函数"""
    log_info("=" * 70)
    log_info("Starting AS phase...")
    log_info(f"Username: {username}")
    log_info(f"AS Address: {cfg.as_addr}")
    
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log_debug(f"Connecting to {cfg.as_addr}...")
        sock.connect(cfg.as_addr)
        local_host, peer_host = _connected_hosts(sock, cfg.as_addr[0])
        log_info("Connected to AS server")
        
        # 构造AS_REQ
        ts1 = int(time.time())
        log_debug(f"Constructing AS_REQ - TS1: {ts1}")
        payload = pack_as_req(username, "TGS", ts1)#打包成协议规定的二进制格式
        log_debug(f"AS_REQ payload length: {len(payload)} bytes")
        
         
        # AS 是一次性TCP连接，SEQ在连接内从1开始。
        seq = 1
        decoded_lines = decrypt_payload(0x01, payload, b'\x00' * 8)  # AS_REQ明文，key不影响
        krb_log_packet(rt, local_host, peer_host, "KRB5",
                    "AS_REQ - Client authentication request",
                    krb_pack(0x01, seq, ts1, payload), decoded_lines)  
        header, resp_payload = send_recv_packet(sock, 0x01, seq, payload, rt, local_host, peer_host)#发送一个 Kerberos 请求包，然后原地等待接收服务器的响应包
        log_info("AS_REQ sent and AS_REP received")
        
        # 解密响应（password作为Kc）
        kc = password.encode().ljust(8)[:8]  # 确保8字节
        log_debug(f"Kc (from password): {kc.hex()}")
        
        # 记录解密前的密文
        log_debug(f"Encrypted AS_REP payload: {len(resp_payload)} bytes")
        hexdump(resp_payload, "Encrypted AS_REP:")
        
        as_rep = unpack_as_rep(resp_payload, kc)# 解包+解密：拿到会话密钥和TGT

        # 使用统一解密函数记录解密后的日志
        full_packet = header.to_bytes() + resp_payload
        header_for_log = KerHeader.from_bytes(full_packet[:20])
        msg_payload = full_packet[20:20 + header_for_log.total_len] if header_for_log.total_len > 0 else full_packet[20:]
        decoded_lines = decrypt_payload(0x02, msg_payload, kc)
        krb_log_packet(rt, peer_host, local_host, "KRB5",
                       "AS_REP decrypted - Key_c_tgs, Ticket_TGS", full_packet, decoded_lines)

        # 更新运行时状态
        rt.bundle.key_c_tgs = as_rep.key_c_tgs
        rt.bundle.ticket_tgs = as_rep.ticket_tgs
        rt.bundle.tgt_expire = as_rep.ts2 + as_rep.lifetime
        
        # 记录解密后的信息
        log_info(f"AS_REP decoded:")
        log_info(f"  Key_C_TGS: {as_rep.key_c_tgs.hex()}")
        log_info(f"  Ticket_TGS length: {len(as_rep.ticket_tgs)} bytes")
        log_info(f"  TS2: {as_rep.ts2}")
        log_info(f"  Lifetime: {as_rep.lifetime}")
        log_info(f"  TGT expires: {as_rep.ts2 + as_rep.lifetime}")
        
        log_state_change(rt.state, "STATE_AS_DONE")
        rt.state = "STATE_AS_DONE"
        rt.logs.append(f"AS phase complete for {username}")
        
        sock.close()
        log_info("AS phase completed successfully")
        log_info("=" * 70)
        return KRB_OK
        
    except Exception as e:
        fail_print = f"AS phase failed: {str(e)}"
        log_error(fail_print)
        log_state_change(rt.state, "STATE_ERROR")
        rt.state = "STATE_ERROR"
        print(fail_print)
        rt.logs.append(fail_print)
        return -1


def client_do_tgs(rt: ClientRuntime, cfg: ClientConfig, id_v: str) -> int:
    """TGS阶段编排函数"""
    log_info("=" * 70)
    log_info("Starting TGS phase...")
    log_info(f"Target Service: {id_v}")
    log_info(f"TGS Address: {cfg.tgs_addr}")
    
    if rt.state != "STATE_AS_DONE":
        log_error(f"TGS phase skipped - current state is {rt.state}, expected STATE_AS_DONE")
        return -1
    
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log_debug(f"Connecting to {cfg.tgs_addr}...")
        sock.connect(cfg.tgs_addr)
        local_host, peer_host = _connected_hosts(sock, cfg.tgs_addr[0])
        log_info("Connected to TGS server")
        
        # 构造TGS_REQ
        ts3 = int(time.time())
        log_debug(f"Constructing TGS_REQ - TS3: {ts3}, ID_V: {id_v}")
        
        payload = pack_tgs_req(id_v, rt.bundle.ticket_tgs, rt.bundle.key_c_tgs,
                              cfg.client_id, cfg.ad_c, ts3) # 打包：构造TGS请求（TGT+认证器）
        log_debug(f"TGS_REQ payload length: {len(payload)} bytes")
        log_debug(f"Using Key_C_TGS: {rt.bundle.key_c_tgs.hex()}")
        log_debug(f"Ticket_TGS length: {len(rt.bundle.ticket_tgs)} bytes")

        # 构建TGS_REQ完整数据包用于日志记录
        tgs_req_header = KerHeader(
            magic=0x4B45,
            version=0x01,
            msg_type=0x03,
            total_len=len(payload),
            seq_num=1,
            timestamp=ts3,
            addition=0
        )
        tgs_req_packet = tgs_req_header.to_bytes() + payload

        # 使用统一解密函数解密TGS_REQ (Ticket_TGS需要K_tgs可能无法解密，Authenticator_c用Key_c_tgs解密)
        decoded_lines = decrypt_payload(0x03, payload, rt.bundle.key_c_tgs)
        krb_log_packet(rt, local_host, peer_host, "KRB5",
                       "TGS_REQ decrypted - Ticket_TGS, Authenticator_c", tgs_req_packet, decoded_lines)

        # TGS 是一次性TCP连接，SEQ在连接内从1开始。
        seq = 1
        header, resp_payload = send_recv_packet(sock, 0x03, seq, payload, rt, local_host, peer_host)# 发送并等待响应
        log_info("TGS_REQ sent and TGS_REP received")
        
        # 解密响应
        log_debug(f"Encrypted TGS_REP payload: {len(resp_payload)} bytes")
        hexdump(resp_payload, "Encrypted TGS_REP:")
        
        tgs_rep = unpack_tgs_rep(resp_payload, rt.bundle.key_c_tgs)# 解包+解密：拿到业务票据和密钥

        # 使用统一解密函数记录解密后的日志
        full_packet = header.to_bytes() + resp_payload
        header_for_log = KerHeader.from_bytes(full_packet[:20])
        msg_payload = full_packet[20:20 + header_for_log.total_len] if header_for_log.total_len > 0 else full_packet[20:]
        decoded_lines = decrypt_payload(0x04, msg_payload, rt.bundle.key_c_tgs)
        krb_log_packet(rt, peer_host, local_host, "KRB5",
                       "TGS_REP decrypted - Key_c_v, Ticket_V", full_packet, decoded_lines)

        # 更新运行时状态
        rt.bundle.key_c_v = tgs_rep.key_c_v
        rt.bundle.ticket_v = tgs_rep.ticket_v
        rt.bundle.tv_expire = tgs_rep.ts4 + tgs_rep.lifetime
        
        # 记录解密后的信息
        log_info(f"TGS_REP decoded:")
        log_info(f"  Key_C_V: {tgs_rep.key_c_v.hex()}")
        log_info(f"  Ticket_V length: {len(tgs_rep.ticket_v)} bytes")
        log_info(f"  TS4: {tgs_rep.ts4}")
        log_info(f"  Lifetime: {tgs_rep.lifetime}")
        log_info(f"  Service Ticket expires: {tgs_rep.ts4 + tgs_rep.lifetime}")
        
        log_state_change(rt.state, "STATE_TGS_DONE")
        rt.state = "STATE_TGS_DONE"
        rt.logs.append(f"TGS phase complete for {cfg.client_id}, service={id_v}")
        
        sock.close()
        log_info("TGS phase completed successfully")
        log_info("=" * 70)
        return KRB_OK
        
    except Exception as e:
        rt.state = "STATE_ERROR"
        fail_print = f"TGS phase failed: {str(e)}"
        log_error(fail_print)
        log_state_change(rt.state, "STATE_ERROR")
        print(fail_print)
        rt.logs.append(fail_print)
        return -1


def client_do_ap(rt: ClientRuntime, cfg: ClientConfig) -> int:
    """AP阶段编排函数"""
    log_info("=" * 70)
    log_info("Starting AP phase...")
    log_info(f"V Address: {cfg.v_addr}")
    
    if rt.state != "STATE_TGS_DONE":
        log_error(f"AP phase skipped - current state is {rt.state}, expected STATE_TGS_DONE")
        return -1
    
    sock = None
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log_debug(f"Connecting to {cfg.v_addr}...")
        sock.connect(cfg.v_addr)
        local_host, peer_host = _connected_hosts(sock, cfg.v_addr[0])
        log_info("Connected to V server")
        
        # 构造AP_REQ
        ts5 = int(time.time())
        log_debug(f"Constructing AP_REQ - TS5: {ts5}")
        
        payload = pack_ap_req(rt.bundle.ticket_v, rt.bundle.key_c_v,
                             cfg.client_id, cfg.ad_c, ts5)
        log_debug(f"AP_REQ payload length: {len(payload)} bytes")
        log_debug(f"Using Key_C_V: {rt.bundle.key_c_v.hex()}")
        log_debug(f"Ticket_V length: {len(rt.bundle.ticket_v)} bytes")
        
        # 发送前立即消费序号；即使服务端返回错误，也不能复用同一个SEQ。
        seq = rt.consume_seq()
        log_debug(f"Using SEQ: {seq}")

        # 构建AP_REQ完整数据包用于日志记录
        ap_req_header = KerHeader(
            magic=0x4B45,
            version=0x01,
            msg_type=0x05,
            total_len=len(payload),
            seq_num=seq,
            timestamp=ts5,
            addition=0
        )
        ap_req_packet = ap_req_header.to_bytes() + payload

        # 使用统一解密函数解密AP_REQ中的Authenticator_c (Ticket_V需要K_v，客户端无法解密)
        decoded_lines = decrypt_payload(0x05, payload, rt.bundle.key_c_v)
        krb_log_packet(rt, local_host, peer_host, "KRB5",
                       "AP_REQ decrypted - Ticket_V, Authenticator_c", ap_req_packet, decoded_lines)

        header, resp_payload = send_recv_packet(sock, 0x05, seq, payload, rt, local_host, peer_host)
        log_info("AP_REQ sent and AP_REP received")
        
        # 验证响应
        log_debug(f"Encrypted AP_REP payload: {len(resp_payload)} bytes")
        hexdump(resp_payload, "Encrypted AP_REP:")
        
        verify_result = verify_ap_rep(resp_payload, rt.bundle.key_c_v, ts5)

        # 记录AP_REP解密后的日志
        full_packet = header.to_bytes() + resp_payload
        decoded_lines = decrypt_payload(0x06, resp_payload, rt.bundle.key_c_v)
        krb_log_packet(rt, peer_host, local_host, "KRB5",
                       "AP_REP decrypted - TS5+1 Verification", full_packet, decoded_lines)

        log_info(f"AP_REP TS verification passed (TS5+1 = {ts5 + 1})")
        
        # 更新运行时状态
        log_state_change(rt.state, "STATE_V_CONNECTED")
        rt.state = "STATE_V_CONNECTED"
        
        # 保存AP socket供调用方验证AP_REP；登录完成后代理层会关闭它。
        # 后续APP业务使用新的TCP连接，并由V根据APP_REQ外层ID_Client绑定已认证会话。
        rt.session_id = f"session_{ts5}"
        rt.v_sock = sock
        log_info(f"Session ID: {rt.session_id}")
        log_info("AP phase completed successfully - V connection established")
        
        rt.logs.append(f"AP phase complete for {cfg.client_id}")
        log_info("=" * 70)
        return KRB_OK
        
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        rt.state = "STATE_ERROR"
        fail_print = f"AP phase failed: {str(e)}"
        log_error(fail_print)
        log_state_change(rt.state, "STATE_ERROR")
        print(fail_print)
        rt.logs.append(fail_print)
        return -1


def client_app_send_frame(rt: ClientRuntime, cfg: ClientConfig,
                          pty_op: int, pty_session_id: int,
                          payload: bytes,
                          expected_events: Optional[set[int]] = None,
                          incidental_events: Optional[list[APPRepPlain]] = None) -> Optional[APPRepPlain]:
    """业务帧发送函数"""
    if rt.state != "STATE_V_CONNECTED":
        msg = f"APP send skipped op={pty_op} session={pty_session_id}: state={rt.state}"
        log_error(msg)
        rt.logs.append(msg)
        return None
    
    try:
        sock = rt.v_sock
        if sock is None:
            raise RuntimeError("V session is not connected")
        
        # 加载私钥
        with open(cfg.privkey_path, 'r') as f:
            priv_key = json.load(f)
        
        # 构造APP_REQ
        seq = rt.consume_seq()
        app_req_payload = pack_app_req(cfg.client_id, rt.bundle.key_c_v,
                                      pty_op, pty_session_id, payload, priv_key, seq)
        
        # 发送请求
        local_host, peer_host = _connected_hosts(sock, cfg.v_addr[0])
        full_packet = send_packet(sock, 0x07, seq, app_req_payload, rt, local_host, peer_host)
        decoded_lines = decrypt_payload(0x07, app_req_payload, rt.bundle.key_c_v)
        krb_log_packet(
            rt,
            local_host,
            peer_host,
            "APP",
            _app_req_info(pty_op, pty_session_id, len(payload)),
            full_packet,
            decoded_lines,
            _signature_status(
                True,
                None,
                cfg.client_id,
                cfg.service_id,
                "APP_REQ is signed by the client; verification is performed by the V server.",
            ),
        )

        deadline = time.time() + 5
        while True:
            timeout = max(0.1, deadline - time.time())
            app_rep = client_app_recv_frame(rt, cfg, timeout=timeout)
            if app_rep is None:
                raise TimeoutError("APP response timeout")
            if expected_events is None or app_rep.pty_event in expected_events:
                break
            if incidental_events is not None:
                incidental_events.append(app_rep)
            if time.time() >= deadline:
                raise TimeoutError("Expected APP event timeout")

        rt.logs.append(f"APP frame complete op={pty_op} session={pty_session_id} event={app_rep.pty_event}")
        return app_rep
        
    except Exception as e:
        msg = f"APP send failed op={pty_op} session={pty_session_id}: {type(e).__name__}: {e}"
        log_error(msg)
        rt.logs.append(msg)
        return None
