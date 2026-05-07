"""Client RESTful API服务器"""

import json
import hashlib
import asyncio
import sys
import os
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import StreamingResponse

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import ClientRuntime, ClientConfig, TicketBundle
from krb.krb import client_do_as, client_do_tgs, client_do_ap, client_app_send_frame


# 全局状态
runtime = ClientRuntime()
config = None


def init_config(config_path: str):
    """初始化配置"""
    global config
    with open(config_path, 'r') as f:
        cfg_data = json.load(f)
    config = ClientConfig(
        client_id=cfg_data['client_id'],
        ad_c=cfg_data['ad_c'],
        as_addr=(cfg_data['as_host'], cfg_data['as_port']),
        tgs_addr=(cfg_data['tgs_host'], cfg_data['tgs_port']),
        v_addr=(cfg_data['v_host'], cfg_data['v_port']),
        cert_path=cfg_data['cert_path'],
        privkey_path=cfg_data['privkey_path']
    )


app = FastAPI(title="Kerberos Client API", version="1.0")


@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """触发Kerberos三阶段认证"""
    global runtime
    
    # 重置状态
    runtime = ClientRuntime()
    
    # AS阶段
    result = client_do_as(runtime, config, username, password)
    if result != 0:
        return {"state": runtime.state, "error": "AS phase failed"}
    
    # TGS阶段
    result = client_do_tgs(runtime, config, "SERVER_V")
    if result != 0:
        return {"state": runtime.state, "error": "TGS phase failed"}
    
    # AP阶段
    result = client_do_ap(runtime, config)
    if result != 0:
        return {"state": runtime.state, "error": "AP phase failed"}
    
    return {
        "state": runtime.state,
        "tgt_expire": runtime.bundle.tgt_expire,
        "tv_expire": runtime.bundle.tv_expire
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
    """SSE实时日志流"""
    async def log_stream():
        last_index = 0
        while True:
            # 检查是否有新日志
            while last_index < len(runtime.logs):
                log_entry = runtime.logs[last_index]
                last_index += 1
                yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'message': log_entry})}\n\n"
            
            await asyncio.sleep(0.1)
    return StreamingResponse(log_stream(), media_type="text/event-stream")


# PTY会话管理
pty_sessions: Dict[str, WebSocket] = {}


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
                
                # 发送OPEN请求到V服务器
                payload = json.dumps({
                    'term': term,
                    'cols': cols,
                    'rows': rows
                }).encode()
                
                result = client_app_send_frame(runtime, config, 0x01, 0, payload)
                if result:
                    session_id = str(result.pty_session_id)
                    pty_sessions[session_id] = websocket
                    
                    await websocket.send_json({
                        'event': 'open_ok',
                        'session_id': session_id
                    })
            
            elif op == 'input':
                # 输入数据
                session_id = data.get('session_id')
                input_data = data.get('data', '')
                
                if session_id and input_data:
                    payload = input_data.encode()
                    result = client_app_send_frame(runtime, config, 0x02, int(session_id), payload)
                    if result:
                        await websocket.send_json({
                            'event': 'output',
                            'session_id': session_id,
                            'data': result.payload.decode('utf-8', errors='ignore')
                        })
            
            elif op == 'resize':
                # 窗口调整
                session_id = data.get('session_id')
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                
                if session_id:
                    payload = json.dumps({'cols': cols, 'rows': rows}).encode()
                    client_app_send_frame(runtime, config, 0x03, int(session_id), payload)
            
            elif op == 'signal':
                # 发送信号
                session_id = data.get('session_id')
                signal = data.get('signal', 'INT')
                
                if session_id:
                    signal_map = {'INT': 2, 'TERM': 15, 'KILL': 9}
                    sig_num = signal_map.get(signal, 2)
                    payload = sig_num.to_bytes(4, 'big')
                    client_app_send_frame(runtime, config, 0x04, int(session_id), payload)
            
            elif op == 'close':
                # 关闭会话
                session_id = data.get('session_id')
                
                if session_id:
                    result = client_app_send_frame(runtime, config, 0x05, int(session_id), b'')
                    if result:
                        await websocket.send_json({
                            'event': 'exit',
                            'session_id': session_id,
                            'exit_code': result.exit_code
                        })
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