# Kerberos Client 模块

## 概述

本模块实现了 Kerberos 客户端的通信加密逻辑和 RESTful API 接口，支持完整的 Kerberos 三阶段认证流程（AS → TGS → AP）以及后续的业务消息交互。

## 目录结构

```
client/proxy/
├── crypto/           # 加密模块
│   ├── __init__.py
│   ├── des.py        # DES-CBC 加密实现
│   ├── sha256.py     # SHA-256 哈希实现
│   └── rsa.py        # RSA-2048 签名实现
├── krb/              # Kerberos 协议模块
│   ├── __init__.py
│   ├── msg.py        # 消息结构定义
│   └── krb.py        # 核心协议逻辑
├── api/              # RESTful API 模块
│   ├── __init__.py
│   └── server.py     # FastAPI 服务器实现
├── main.py           # 主入口
├── client_config.json # 配置文件
├── setup.py          # 安装配置
└── readme.md         # 说明文档
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 配置说明

修改 `client_config.json` 文件：

```json
{
    "client_id": "CLIENT_001",
    "ad_c": 0,
    "as_host": "127.0.0.1",
    "as_port": 8881,
    "tgs_host": "127.0.0.1",
    "tgs_port": 8882,
    "v_host": "127.0.0.1",
    "v_port": 8883,
    "cert_path": "../certs/cert_client.json",
    "privkey_path": "../keys/client_priv.json",
    "ticket_store_path": "./tickets/ticket.bin"
}
```

## 启动方式

```bash
python main.py --config client_config.json --host 0.0.0.0 --port 9883
```

## API 接口

### 1. 登录认证

**POST /api/login**

请求：
```json
{
    "username": "CLIENT_001",
    "password": "password"
}
```

如果本地二进制票据缓存中的 `Ticket_V` 尚未过期，`username` 和 `password` 可以留空，Client 会直接复用缓存票据执行 AP 握手。

响应：
```json
{
    "state": "STATE_V_CONNECTED",
    "tgt_expire": 1746441825,
    "tv_expire": 1746441825
}
```

### 2. 获取状态

**GET /api/state**

响应：
```json
{
    "state": "STATE_V_CONNECTED",
    "k_ctgs_sha256": "a1b2c3d4...",
    "k_cv_sha256": "e5f6g7h8...",
    "tgt_expire": 1746441825,
    "tv_expire": 1746441825,
    "seq_num": 4
}
```

### 3. 获取证书

**GET /api/cert**

响应：
```json
{
    "id": "CLIENT_001",
    "issuer": "MY_ROOT_CA",
    "public_key": {
        "n": "...",
        "e": "010001"
    },
    "expire": "2026-12-31",
    "sign": "..."
}
```

### 4. 实时日志

**GET /api/logs (SSE)**

返回实时日志流。

### 5. PTY WebSocket

**WS /ws/pty**

帧格式：

**Web -> Client:**
```json
{
    "op": "open|input|resize|signal|close",
    "session_id": "12345",
    "data": "base64_encoded_data",
    "cols": 80,
    "rows": 24,
    "signal": "INT|TERM|KILL"
}
```

**Client -> Web:**
```json
{
    "event": "open_ok|output|exit|error",
    "session_id": "12345",
    "data": "base64_encoded_data",
    "exit_code": 0
}
```

## 核心功能

### 加密算法

- **DES-CBC**: 对称加密，用于加密票据和认证器
- **SHA-256**: 哈希函数，用于生成消息摘要
- **RSA-2048**: 非对称加密，用于数字签名

### Kerberos 阶段

1. **AS 阶段**: 获取 TGT（Ticket Granting Ticket）
2. **TGS 阶段**: 获取服务票据（Service Ticket）
3. **AP 阶段**: 与应用服务器进行双向认证
4. **业务阶段**: 发送 PTY 指令并接收响应

### 状态机

```
STATE_INIT → STATE_AS_DONE → STATE_TGS_DONE → STATE_V_CONNECTED
       ↑                              │
       └──────────────────────────────┘
            (过期或错误时回退)
```

## 安全特性

- RSA 数字签名实现双向不可否认
- DES-CBC 加密保护敏感通信
- 序列号防重放攻击
- 时间戳验证防止消息延迟攻击

## 注意事项

1. 全流程认证时密码必须为 8 字节以适配 DES 加密要求，复用未过期 `Ticket_V` 时可留空
2. RSA 私钥必须严格保存在本地，不进行网络传输
3. 所有网络传输使用大端序字节序
4. 证书和密钥文件需要预先生成
5. `Ticket_V` 和 `Key_c_v` 会以二进制块持久化到 `ticket_store_path`

## 测试

```bash
# 测试 DES 加密
python -c "from crypto.des import encrypt_des_cbc, decrypt_des_cbc; key = b'12345678'; plain = b'hello12'; cipher = encrypt_des_cbc(key, plain); print(decrypt_des_cbc(key, cipher))"

# 测试 SHA-256
python -c "from crypto.sha256 import sha256; print(sha256(b'hello').hex())"
```
