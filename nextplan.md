# 跳板机架构改造计划

本文档记录将当前 V 服务从“本地 PTY 终端服务器”改造成“Kerberos 认证的 SSH 跳板机”时需要修改的部分。

## 1. 总体结论

当前 Kerberos 报文外层格式不需要修改。

保持不变的部分：

- `Ker_Header` 20 字节通用报文头。
- `AS_REQ / AS_REP`。
- `TGS_REQ / TGS_REP`。
- `AP_REQ / AP_REP`。
- `APP_REQ / APP_REP` 外层结构。
- `Ticket_V` 的结构和用法。
- `Key_c_v` 的用法。
- RSA 签名规则：`Seq_Num || Cipher_Data`。

需要修改的是 `MsgType=0x07` 的业务层语义，主要是打开终端时的 `Payload` 内容，以及 V 端从“启动本地 shell”改为“连接远端 SSH 并申请远端 PTY”。

## 2. 新架构

目标架构：

```text
Client
  | Kerberos AP + APP 加密通道
  v
V 跳板机
  | SSH 协议
  v
多个 SSH Server
```

Kerberos 负责：

- Client 到 V 的身份认证。
- Client 与 V 之间 APP 消息加密。
- 后续业务帧签名和验签。
- V 端基于 `ID_Client` 做授权和审计。

SSH 负责：

- V 到后端 SSH Server 的远端登录。
- 远端 PTY 分配。
- 远端 shell 输入输出。

`Key_c_v` 不作为 SSH 密码使用，也不发送给 SSH Server。

## 3. 协议修改

### 3.1 不修改通用报文头

不修改：

```text
magic
version
msg_type
total_len
seq_num
timestamp
addition
```

原因：

- 当前 `MsgType=0x07` 已经承载认证后的业务消息。
- `APP_REQ` 内层已经有 `PTY_Op + PTY_Session_ID + Payload_Len + Payload`，可以通过扩展业务 `Payload` 完成跳板机目标选择。
- 修改通用头会影响 AS/TGS/V/Client 全链路兼容性，收益很低。

### 3.2 不修改 Kerberos 票据

不修改：

```text
TGS_REQ.ID_V
TGS_REP.Key_c_v
TGS_REP.Ticket_V
Ticket_V.ID_V
AP_REQ
AP_REP
```

`ID_V` 仍然表示 V 跳板机服务，例如：

```text
jump_server
```

后端 SSH 目标不放进 `Ticket_V`。后端目标属于 V 的业务授权范围，不属于 Kerberos 服务票据签发范围。

### 3.3 扩展 APP_REQ 内层 PTY_Op

当前文档中 `PTY_Op` 为：

```text
0x01 = OPEN
0x02 = INPUT
0x03 = RESIZE
0x04 = SIGNAL
0x05 = CLOSE
```

建议扩展为：

```text
0x01 = OPEN_LOCAL
0x02 = INPUT
0x03 = RESIZE
0x04 = SIGNAL
0x05 = CLOSE
0x06 = OPEN_SSH
```

说明：

- `OPEN_LOCAL` 保留原有本地 PTY 行为，便于兼容和调试。
- `OPEN_SSH` 用于打开后端 SSH 目标。
- `INPUT / RESIZE / SIGNAL / CLOSE` 继续复用原语义，对本地 PTY 和 SSH remote PTY 都适用。

### 3.4 新增 OPEN_SSH Payload 格式

`APP_REQ` 外层保持不变：

```text
ID_Client + Cipher_Len + Cipher_Data + RSA_Sign_c
```

`Cipher_Data` 解密后保持不变：

```text
PTY_Op(uint8)
PTY_Session_ID(uint32)
Payload_Len(uint32)
Payload(bytes)
```

新增 `OPEN_SSH` 的 `Payload`：

```text
TargetIDLen(uint16)
TargetID(bytes)
TermLen(uint16)
Term(bytes)
Cols(uint16)
Rows(uint16)
```

字段说明：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `TargetIDLen` | `uint16` | 后端 SSH 目标 ID 长度 |
| `TargetID` | `bytes` | 后端 SSH 目标 ID，例如 `prod-1` |
| `TermLen` | `uint16` | 终端类型字符串长度 |
| `Term` | `bytes` | 终端类型，例如 `xterm-256color` |
| `Cols` | `uint16` | 终端列数 |
| `Rows` | `uint16` | 终端行数 |

原 `OPEN_LOCAL` 的 `Payload` 可保持：

```text
TermLen(uint16)
Term(bytes)
Cols(uint16)
Rows(uint16)
```

## 4. V 配置修改

V 的 `config.json` 增加 `ssh_targets`。

配置示例（`ssh_user` 和 `REPLACE_WITH_SSH_PASSWORD` 为占位符，请按目标主机分别配置）：

```json
{
  "node_id": "verify_server",
  "listen_host": "0.0.0.0",
  "listen_port": 8883,
  "k_v_hex": "4b564b4559313233",
  "ssh_targets": [
    {
      "id": "prod-1",
      "host": "10.0.0.11",
      "port": 22,
      "ssh_user": "ssh_user",
      "auth_type": "password",
      "password": "REPLACE_WITH_SSH_PASSWORD",
      "known_hosts_path": "./keys/known_hosts",
      "allowed_clients": ["CLIENT_1", "CLIENT_2"]
    },
    {
      "id": "test-1",
      "host": "10.0.0.21",
      "port": 22,
      "ssh_user": "ssh_user",
      "auth_type": "password",
      "password": "REPLACE_WITH_SSH_PASSWORD",
      "allowed_clients": ["CLIENT_1"]
    }
  ]
}
```

建议字段：

| 字段 | 说明 |
| --- | --- |
| `id` | 前端和 Client 选择的目标 ID |
| `host` | SSH Server 地址 |
| `port` | SSH 端口 |
| `ssh_user` | V 登录后端 SSH 使用的用户 |
| `auth_type` | `private_key` 或 `password`；当前简化部署推荐 `password` |
| `key_path` | 私钥路径 |
| `password` | `password` 模式可直接配置的 SSH 密码 |
| `password_path` | 可选，密码文件路径 |
| `known_hosts_path` | 可选，SSH known_hosts 文件路径；未配置时当前实现使用宽松主机密钥校验 |
| `allowed_clients` | 允许访问该目标的 Kerberos Client ID 列表 |

## 4.1 AP 与 APP 连接生命周期修改

AP 认证连接只用于 Kerberos AP_REQ/AP_REP 互认证。认证成功后，V 在内存中保存以 `ID_Client` 索引的 Kerberos Session，包括 `K_c,v`、Ticket 过期时间和 APP replay window；Client 关闭 AP TCP 连接后，不删除 V 端 Kerberos Session。

后续终端业务使用独立 APP TCP 连接：

1. Client 后端打开新的 TCP 连接到 V。
2. Client 直接发送 `APP_REQ`，不重复发送 `AP_REQ`。
3. V 先解析 `APP_REQ` 外层明文 `ID_Client`，查找已经 AP 认证过的 Kerberos Session。
4. V 使用该 Session 中的 `K_c,v` 验签、解密 APP payload，并执行 `OPEN_SSH`、`INPUT`、`RESIZE`、`SIGNAL`、`CLOSE`。
5. APP TCP 断开或 PTY close 只关闭当前 SSH remote PTY，不删除 Kerberos Session。
6. Ticket_V 过期时才删除/拒绝该 Kerberos Session，Client 需要重新走 TGS + AP。

因此：Client 端不需要 SSH target 配置，也不需要 SSH 用户名密码；SSH 目标、用户名、密码和授权列表只在 V 的 `ssh_targets` 中配置。

## 5. V 服务端代码修改

### 5.1 配置结构

修改：

```text
verify_server/config/config.go
```

新增结构：

```go
type SSHTarget struct {
    ID             string   `json:"id"`
    Host           string   `json:"host"`
    Port           int      `json:"port"`
    SSHUser        string   `json:"ssh_user"`
    AuthType       string   `json:"auth_type"`
    KeyPath        string   `json:"key_path,omitempty"`
    Password       string   `json:"password,omitempty"`
    PasswordPath   string   `json:"password_path,omitempty"`
    KnownHostsPath string   `json:"known_hosts_path,omitempty"`
    AllowedClients []string `json:"allowed_clients"`
}
```

在 `Config` 中增加：

```go
SSHTargets []SSHTarget `json:"ssh_targets"`
```

校验规则：

- `id` 不能为空。
- `host` 不能为空。
- `port > 0`。
- `ssh_user` 不能为空。
- `auth_type` 支持 `private_key` 和 `password`。
- `private_key` 模式下 `key_path` 必填。
- `password` 模式下 `password` 或 `password_path` 至少配置一个。
- `allowed_clients` 为空时建议表示不允许任何人访问，避免默认开放。

### 5.2 终端 Session 抽象

当前 V 使用 SSH remote PTY：

```text
verify_server/service/pty
```

终端抽象：

```text
verify_server/service/pty
  protocol.go       // Op/Open/Resize/Signal payload 编解码
  session.go        // 统一接口
  ssh_session.go    // SSH remote PTY
```

统一接口建议：

```go
type Session interface {
    Write([]byte) (int, error)
    Resize(cols, rows uint16) error
    Signal(sig uint8) error
    Close() error
    Output() io.Reader
}
```

本地 shell PTY 分支已移除，`pty.Session` 只承载 SSH 会话读写和回调。

### 5.3 SSH remote PTY 实现

使用：

```go
golang.org/x/crypto/ssh
```

核心流程：

```go
client, err := ssh.Dial("tcp", hostPort, sshConfig)
session, err := client.NewSession()
stdin, err := session.StdinPipe()
stdout, err := session.StdoutPipe()
stderr, err := session.StderrPipe()
session.RequestPty(term, int(rows), int(cols), ssh.TerminalModes{})
session.Shell()
```

输出流需要合并 stdout/stderr 后进入现有 `StreamOutput` 逻辑。

### 5.4 APP OPEN 处理

修改：

```text
verify_server/service/app.go
```

当前逻辑：

```go
case pty.OpOpenSSH:
    targetID, term, cols, rows := ParseOpenSSHPayload(...)
    target := s.lookupSSHTarget(targetID)
    s.checkTargetPermission(current.IDClient, target)
    sshSession := pty.StartSSHSession(target, term, cols, rows)
```

权限检查：

```text
Ticket_V.IDClient == current.IDClient
current.IDClient in target.allowed_clients
```

### 5.5 SessionContext 增加目标信息

修改：

```text
verify_server/service/context.go
```

新增字段：

```go
TargetID   string
TargetHost string
SSHUser    string
```

用于审计、WebUI 展示、关闭会话和问题定位。

## 6. Client 代理修改

### 6.1 WebSocket open 参数

当前 `/ws/pty` open 帧只需要：

```text
term
cols
rows
```

新增：

```text
target_id
```

示例：

```json
{
  "op": "open",
  "target_id": "prod-1",
  "term": "xterm-256color",
  "cols": 120,
  "rows": 30
}
```

### 6.2 Client APP 打包

修改：

```text
client/proxy/krb/msg.py
client/proxy/krb/krb.py
client/proxy/api/server.py
```

新增：

```python
PTY_OP_OPEN_SSH = 0x06
```

新增 `OPEN_SSH` payload 打包：

```text
TargetIDLen + TargetID + TermLen + Term + Cols + Rows
```

发送时：

```text
pty_op = 0x06
pty_session_id = 0
payload = open_ssh_payload
```

### 6.3 前端目标选择

Client 前端需要在终端打开前选择目标 ID。权威目标配置只在 V；Client 认证到 V 后，由 Client proxy 通过 V Web API 拉取节点列表，并在前端下拉框中选择。

建议新增接口：

```text
GET /api/targets
```

返回：

```json
{
  "targets": [
    {"id": "prod-1", "host": "10.0.0.11", "ssh_user": "ops"},
    {"id": "test-1", "host": "10.0.0.21", "ssh_user": "dev"}
  ]
}
```

注意：

- 该接口从 V Web API 的 `/api/targets` 拉取列表。
- 不返回 SSH 私钥路径。
- 不返回密码。
- 最终目标是否存在、当前 Client 是否有权限，仍由 V 端 `ssh_targets` 校验。

## 7. 审计修改

### 7.1 审计记录字段

V 审计记录增加：

```text
target_id
target_host
ssh_user
```

适用事件：

- `APP_REQ OPEN_SSH`
- `APP_REP OPEN_OK`
- `INPUT`
- `OUTPUT`
- `RESIZE`
- `SIGNAL`
- `CLOSE`
- `EXIT`
- `ERROR`

### 7.2 Web API 修改

修改 V Web API：

```text
GET /api/sessions
GET /api/audit/session/:id
GET /api/audit/replay/:id
GET /api/pty_log
```

增加返回字段：

```json
{
  "target_id": "prod-1",
  "target_host": "10.0.0.11",
  "ssh_user": "ops"
}
```

### 7.3 审计原则

应记录：

- 谁访问了哪个目标。
- 何时打开和关闭会话。
- 输入输出帧大小。
- 输出回放数据。
- 认证、授权、验签、解密结果。

谨慎记录：

- 明文输入命令。
- SSH 凭据。
- Kerberos session key。

禁止记录：

- SSH 私钥内容。
- SSH 密码。
- `Key_c_v` 明文。
- `K_c_tgs` 明文。

## 8. 文档修改

需要更新：

```text
docs/Kerberos设计文档1.2.md
```

建议更新章节：

### 8.1 第一章或总体说明

将：

```text
基于 Xterm.js 和 Go PTY 实现零信任访问审计系统
```

调整为：

```text
基于 Xterm.js、Kerberos APP 加密通道和 SSH remote PTY 实现零信任跳板机访问审计系统
```

### 8.2 配置文件模板

V 节点配置增加：

```text
ssh_targets
```

### 8.3 第五章 V 应用服务器模块

将：

```text
V 创建 Go PTY 会话，启动本地 shell
```

调整为：

```text
V 根据 OPEN_SSH 中的 target_id 查找 SSH 目标，完成授权后连接后端 SSH Server，并通过 SSH RequestPty 创建远端 PTY
```

### 8.4 第九章 APP_REQ Payload 语义

增加：

```text
0x06 = OPEN_SSH
```

增加 `OPEN_SSH` payload 格式：

```text
TargetIDLen(uint16) + TargetID(bytes) + TermLen(uint16) + Term(bytes) + Cols(uint16) + Rows(uint16)
```

### 8.5 第六章 Client 模块

`/ws/pty` 帧语义增加：

```text
target_id
```

### 8.6 审计 Web API

审计响应增加：

```text
target_id
target_host
ssh_user
```

## 9. 测试计划

### 9.1 协议单元测试

新增测试：

- `OPEN_SSH` payload 编码和解析。
- `target_id` 长度为 0 时拒绝。
- `cols/rows` 为 0 时拒绝。
- 超长 `target_id` 拒绝。

### 9.2 V 授权测试

新增测试：

- `CLIENT_1` 访问允许目标成功。
- `CLIENT_1` 访问未授权目标失败。
- 不存在的 `target_id` 失败。
- `allowed_clients` 为空时拒绝。

### 9.3 SSH 会话测试

新增测试：

- 使用测试 SSH Server 打开 shell。
- 输入命令后收到输出。
- resize 不断开。
- close 能释放 SSH session 和 client。

### 9.4 端到端测试

覆盖：

```text
AS -> TGS -> AP -> OPEN_SSH -> INPUT -> OUTPUT -> CLOSE
```

验证：

- `Ticket_V` 仍然只认证 V。
- `Key_c_v` 仍然只加密 C<->V。
- SSH 私钥只存在 V 侧。
- 审计中能看到 `target_id`。

## 10. 推荐实施顺序

1. 更新文档中的协议语义，明确 `OPEN_SSH`。
2. V 配置增加 `ssh_targets` 和校验逻辑。
3. Client 代理增加 `OPEN_SSH` payload 打包。
4. V 增加 `OPEN_SSH` payload 解析和授权检查。
5. 新增 SSH remote PTY session 实现。
6. 将 `app.go` 的 `OPEN_SSH` 分支接入 SSH session。
7. Client 前端增加目标选择。
8. 审计字段增加目标信息。
9. 补充单元测试和端到端测试。

## 11. 不建议的方案

### 11.1 不建议把后端 SSH 目标放进 Ticket_V

原因：

- 每切换一个 SSH 目标都需要重新请求 TGS。
- TGS 需要理解所有 SSH 目标，耦合过重。
- 后端授权属于 V 的业务策略，不是 Kerberos 票据层职责。

### 11.2 不建议让 Client 提交 SSH 密码

原因：

- 密码会进入 Client、V、日志、内存和网络处理链路，风险更大。
- 跳板机模型更适合由 V 托管 SSH 凭据。
- 客户端只需要 Kerberos 身份，后端访问由 V 按授权策略代理。

### 11.3 不建议修改通用报文头

原因：

- 当前扩展点足够。
- 修改头部会影响所有节点。
- 会破坏文档中 `version=0x01` 的兼容约束。
