"""Client RESTful API服务器"""

import json
import hashlib
import asyncio
import sys
import os
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import ClientRuntime, ClientConfig, TicketBundle
from krb.krb import client_do_as, client_do_tgs, client_do_ap, client_app_send_frame, client_app_recv_frame


PTY_EVENT_OPEN_OK = 0x11
PTY_EVENT_OUTPUT = 0x12
PTY_EVENT_EXIT = 0x13
PTY_EVENT_ERROR = 0x14


# 全局状态
runtime = ClientRuntime()
config = None


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
    config = ClientConfig(
        client_id=cfg_data['client_id'],
        ad_c=cfg_data['ad_c'],
        as_addr=(cfg_data['as_host'], cfg_data['as_port']),
        tgs_addr=(cfg_data['tgs_host'], cfg_data['tgs_port']),
        v_addr=(cfg_data['v_host'], cfg_data['v_port']),
        cert_path=resolve_path(cfg_data['cert_path']),
        privkey_path=resolve_path(cfg_data['privkey_path']),
        service_id=cfg_data.get('service_id', 'verify_server')
    )


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
async def login(username: str = Form(...), password: str = Form(...)):
    """触发Kerberos三阶段认证"""
    global runtime
    
    if runtime.v_sock is not None:
        try:
            runtime.v_sock.close()
        except Exception:
            pass

    # 每次登录建立新的 Kerberos 连接上下文，协议SEQ从该连接上下文重新开始。
    runtime = ClientRuntime()
    config.client_id = username
    runtime.logs.append(f"Login started for {username}")
    
    # AS阶段
    result = client_do_as(runtime, config, username, password)
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
    runtime.logs.append(f"Login completed for {username}")
    
    import uuid
    runtime.session_id = str(uuid.uuid4())
    
    return {
        "state": runtime.state,
        "tgt_expire": runtime.bundle.tgt_expire,
        "tv_expire": runtime.bundle.tv_expire,
        "session_id": runtime.session_id
    }


@app.get("/api/state")
async def get_state():
    """获取当前Client状态"""
    return {
        "state": runtime.state,
        "k_ctgs_sha256": hashlib.sha256(runtime.bundle.key_c_tgs).hexdigest() if runtime.bundle.key_c_tgs else "",
        "k_cv_sha256": hashlib.sha256(runtime.bundle.key_c_v).hexdigest() if runtime.bundle.key_c_v else "",
        "tgt_expire": runtime.bundle.tgt_expire,
        "tv_expire": runtime.bundle.tv_expire,
        "seq_num": runtime.seq_num
    }


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


# PTY会话管理
pty_sessions: Dict[str, WebSocket] = {}


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
        event = client_app_recv_frame(runtime, timeout=0.05)
        if event is None:
            return
        await send_pty_event(websocket, event)


@app.websocket("/ws/pty")
async def websocket_pty(websocket: WebSocket):
    """PTY长连接会话"""
    await websocket.accept()
    
    session_id = None
    try:
        while True:
            data = await websocket.receive_json()
            op = data.get('op', '')
            
            if op == 'open':
                # 打开新会话
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                term = data.get('term', 'xterm')

                if runtime.state != "STATE_V_CONNECTED":
                    await websocket.send_json({
                        'event': 'error',
                        'message': f'PTY open failed: client not authenticated (state={runtime.state}).'
                    })
                    continue
                
                term_raw = term.encode()
                payload = len(term_raw).to_bytes(2, 'big') + term_raw + cols.to_bytes(2, 'big') + rows.to_bytes(2, 'big')
                
                incidental = []
                result = client_app_send_frame(runtime, config, 0x01, 0, payload, {PTY_EVENT_OPEN_OK, PTY_EVENT_ERROR}, incidental)
                if result:
                    session_id = str(result.pty_session_id)
                    pty_sessions[session_id] = websocket
                    await forward_incidental_events(websocket, incidental)
                    await send_pty_event(websocket, result)
                    await drain_available_pty_events(websocket)
                else:
                    await forward_incidental_events(websocket, incidental)
                    await websocket.send_json({
                        'event': 'error',
                        'message': 'PTY open failed: no response from V server.'
                    })
            
            elif op == 'input':
                # 输入数据 - 按照设计文档：Web -> Client 的 data 字段是 base64 编码
                session_id = data.get('session_id')
                input_data = data.get('data', '')
                
                if session_id and input_data:
                    # base64 解码
                    payload = base64.b64decode(input_data)
                    incidental = []
                    result = client_app_send_frame(runtime, config, 0x02, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
                        await drain_available_pty_events(websocket)
            
            elif op == 'resize':
                # 窗口调整
                session_id = data.get('session_id')
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                
                if session_id:
                    payload = cols.to_bytes(2, 'big') + rows.to_bytes(2, 'big')
                    incidental = []
                    result = client_app_send_frame(runtime, config, 0x03, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
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
                    result = client_app_send_frame(runtime, config, 0x04, int(session_id), payload, {PTY_EVENT_OUTPUT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
            
            elif op == 'close':
                # 关闭会话
                session_id = data.get('session_id')
                
                if session_id:
                    incidental = []
                    result = client_app_send_frame(runtime, config, 0x05, int(session_id), b'', {PTY_EVENT_EXIT, PTY_EVENT_ERROR}, incidental)
                    await forward_incidental_events(websocket, incidental)
                    if result:
                        await send_pty_event(websocket, result)
                    if session_id in pty_sessions:
                        del pty_sessions[session_id]
                    break
    
    except WebSocketDisconnect:
        if session_id and session_id in pty_sessions:
            del pty_sessions[session_id]
    except Exception as e:
        if session_id and session_id in pty_sessions:
            del pty_sessions[session_id]
        await websocket.send_json({
            'event': 'error',
            'message': str(e)
        })
