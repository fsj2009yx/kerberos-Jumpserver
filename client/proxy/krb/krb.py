"""Kerberos客户端核心逻辑"""

import socket
import time
import json
import sys
import os
from typing import Optional

# 添加当前目录到路径，支持直接运行
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import *
from crypto.des import encrypt_des_cbc, decrypt_des_cbc
from crypto.sha256 import sha256
from crypto.rsa import rsa_sign


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


def send_packet(sock: socket.socket, msg_type: int, seq_num: int, payload: bytes):
    """发送一个Kerberos协议包"""
    timestamp = int(time.time())
    packet = krb_pack(msg_type, seq_num, timestamp, payload)
    sock.sendall(packet)


def recv_packet(sock: socket.socket) -> tuple[KerHeader, bytes]:
    """接收一个Kerberos协议包"""
    header_raw = krb_recv_full(sock, 20)
    header = KerHeader.from_bytes(header_raw)

    if header.magic != 0x4B45:
        raise ValueError("Response magic mismatch")

    if header.msg_type == 0xff:
        error_data = krb_recv_full(sock, header.total_len)
        error_code = int.from_bytes(error_data, 'big', signed=True)
        raise RuntimeError(f"Server error: {error_code}")

    payload_raw = krb_recv_full(sock, header.total_len)
    return header, payload_raw


def send_recv_packet(sock: socket.socket, msg_type: int, seq_num: int,
                     payload: bytes) -> tuple[KerHeader, bytes]:
    """发送请求并接收响应"""
    send_packet(sock, msg_type, seq_num, payload)
    return recv_packet(sock)


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


def unpack_app_rep(payload: bytes, key_c_v: bytes) -> APPRepPlain:
    """解包APP_REP"""
    app_rep = APPRepPayload.from_bytes(payload)
    plain_data = decrypt_des_cbc(key_c_v, app_rep.cipher_data)
    return APPRepPlain.from_bytes(plain_data)


def client_app_recv_frame(rt: ClientRuntime, timeout: Optional[float] = None) -> Optional[APPRepPlain]:
    """从已认证的V连接上读取一个APP响应帧。timeout到期时返回None。"""
    sock = rt.v_sock
    if sock is None:
        raise RuntimeError("V session is not connected")

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
        raise RuntimeError(f"Unexpected APP response type: {header.msg_type}")
    return unpack_app_rep(resp_payload, rt.bundle.key_c_v)


def client_do_as(rt: ClientRuntime, cfg: ClientConfig, username: str, password: str) -> int:
    """AS阶段编排函数"""
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(cfg.as_addr)
        
        # 构造AS_REQ
        ts1 = int(time.time())
        payload = pack_as_req(username, "TGS", ts1)
        
        # AS 是一次性TCP连接，SEQ在连接内从1开始。
        seq = 1
        send_packet(sock, 0x01, seq, payload)
        header, resp_payload = recv_packet(sock)
        
        # 解密响应（password作为Kc）
        kc = password.encode().ljust(8)[:8]  # 确保8字节
        as_rep = unpack_as_rep(resp_payload, kc)
        
        # 更新运行时状态
        rt.bundle.key_c_tgs = as_rep.key_c_tgs
        rt.bundle.ticket_tgs = as_rep.ticket_tgs
        rt.bundle.tgt_expire = as_rep.ts2 + as_rep.lifetime
        rt.state = "STATE_AS_DONE"
        rt.logs.append(f"AS phase complete for {username}")
        
        sock.close()
        return KRB_OK
        
    except Exception as e:
        fail_print = f"AS phase failed: {str(e)}"
        rt.state = "STATE_ERROR"
        print(fail_print)
        rt.logs.append(fail_print)
        return -1


def client_do_tgs(rt: ClientRuntime, cfg: ClientConfig, id_v: str) -> int:
    """TGS阶段编排函数"""
    if rt.state != "STATE_AS_DONE":
        return -1
    
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(cfg.tgs_addr)
        
        # 构造TGS_REQ
        ts3 = int(time.time())
        payload = pack_tgs_req(id_v, rt.bundle.ticket_tgs, rt.bundle.key_c_tgs,
                              cfg.client_id, cfg.ad_c, ts3)
        
        # TGS 是一次性TCP连接，SEQ在连接内从1开始。
        seq = 1
        send_packet(sock, 0x03, seq, payload)
        header, resp_payload = recv_packet(sock)
        
        # 解密响应
        tgs_rep = unpack_tgs_rep(resp_payload, rt.bundle.key_c_tgs)
        
        # 更新运行时状态
        rt.bundle.key_c_v = tgs_rep.key_c_v
        rt.bundle.ticket_v = tgs_rep.ticket_v
        rt.bundle.tv_expire = tgs_rep.ts4 + tgs_rep.lifetime
        rt.state = "STATE_TGS_DONE"
        rt.logs.append(f"TGS phase complete for {cfg.client_id}, service={id_v}")
        
        sock.close()
        return KRB_OK
        
    except Exception as e:
        rt.state = "STATE_ERROR"
        fail_print = f"TGS phase failed: {str(e)}"
        print(fail_print)
        rt.logs.append(fail_print)
        return -1


def client_do_ap(rt: ClientRuntime, cfg: ClientConfig) -> int:
    """AP阶段编排函数"""
    if rt.state != "STATE_TGS_DONE":
        return -1
    
    sock = None
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(cfg.v_addr)
        
        # 构造AP_REQ
        ts5 = int(time.time())
        payload = pack_ap_req(rt.bundle.ticket_v, rt.bundle.key_c_v,
                             cfg.client_id, cfg.ad_c, ts5)
        
        # 发送前立即消费序号；即使服务端返回错误，也不能复用同一个SEQ。
        seq = rt.consume_seq()
        send_packet(sock, 0x05, seq, payload)
        header, resp_payload = recv_packet(sock)
        
        # 验证响应
        verify_ap_rep(resp_payload, rt.bundle.key_c_v, ts5)
        
        # 更新运行时状态
        rt.state = "STATE_V_CONNECTED"
        
        # 保存socket用于后续业务通信；V 服务要求 AP 和 APP 在同一 TCP 连接上。
        rt.session_id = f"session_{ts5}"
        rt.v_sock = sock
        rt.logs.append(f"AP phase complete for {cfg.client_id}")
        return KRB_OK
        
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        rt.state = "STATE_ERROR"
        fail_print = f"AP phase failed: {str(e)}"
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
        send_packet(sock, 0x07, seq, app_req_payload)

        deadline = time.time() + 5
        while True:
            timeout = max(0.1, deadline - time.time())
            app_rep = client_app_recv_frame(rt, timeout=timeout)
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
        rt.logs.append(f"APP send failed: {str(e)}")
        return None
