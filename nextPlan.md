# Next Plan

## 当前模型确认

当前项目采用简化堡垒机模型：`V_server` 同时承担跳板机和目标机角色，Client 通过 Kerberos 完成身份认证后访问 `V_server` 本地 PTY，也就是当前配置中的 `/bin/sh`。

在这个模型下，不需要额外引入 SSH。审计边界应放在 `V_server` 的 PTY 代理层：Client 的输入帧、PTY 的输出帧、会话打开/关闭、验签结果、错误结果都由 `V_server` 统一记录。

## 已具备能力

- AS -> TGS -> V 的 Kerberos 三阶段认证链路已跑通。
- Client 可以通过 Web API 触发登录，并进入 `STATE_V_CONNECTED`。
- V 端可以校验服务票据和 Authenticator，建立会话。
- Client -> V 的 APP_REQ 已使用 `K_c_v` 加密，并由 Client RSA 私钥签名。
- V 端已对 APP_REQ 做 Client RSA 签名校验。
- V 端可以启动本地 PTY，处理 open/input/resize/signal/close。
- Client Web 前端已有 Login、Logs、Xterm Terminal 基础页面。
- Client `/api/logs` 已能以 SSE 形式返回通信包日志。

## 缺失部分

### 1. V 端审计持久化

当前 V 端只有运行日志和内存计数，尚未把 PTY 审计事件作为结构化数据落盘。

需要新增本地审计存储，建议先用 SQLite，记录：

- 会话 ID
- Client ID
- Client IP / AD_c
- PTY session ID
- 用户端完整命令输入

### 2. V 端审计查询接口

文档和 V WebUI 已声明但 Go 后端未实现以下接口：

- `GET /api/auth_log?limit=100`
- `GET /api/pty_log?limit=100`
- `GET /api/audit/session/:id`
- `GET /api/audit/replay/:id`

需要让这些接口直接读取审计存储，而不是只读取运行日志。

### 3. 会话回放能力

堡垒机审计系统需要能够复现会话过程。

需要基于 PTY 输出帧实现最小回放：

- 按时间顺序取出某个 `pty_session_id` 的 output 帧。
- 保留每帧时间间隔。
- 前端用 xterm 只读播放输出。
- 输入帧可作为旁路时间线展示，不直接写入回放终端。

### 4. Client 对 V 返回帧验签

V 端已经对 APP_REP 做 RSA 签名，但 Client 当前解包 APP_REP 时只解密，没有校验 `rsa_sign_v`。

需要补齐：

- Client 配置中加入 V 证书或 V 公钥路径。
- Client 收到 APP_REP 后先校验 `Seq_Num || Cipher_Data` 的 V 签名。
- 验签通过后再解密 APP_REP。
- 验签失败时断开 V 会话并进入 `STATE_ERROR`。

### 4.2 Client本地持久化存储Ticket票据

需要补齐：
- Client 本地持久化存储 Kerberos 票据（AS/TGS）。
- 初始化启动时加载票据，避免每次登录都要重新走 Kerberos 认证。
- 票据未过期则不用登录，直接用现有票据访问 V。
- 票据过期时自动删除本地票据文件，提示用户重新登录。

### 5. 证书校验闭环

当前 V 端加载 Client 证书后直接取公钥验 APP_REQ，未强制调用证书有效性校验。

需要补齐：

- V 启动时对 Client 证书执行 `CertVerify`。
- 校验证书过期时间。
- 校验证书签名。
- 校验证书 ID 与配置中的 Client ID 一致。
- 证书校验失败时拒绝该 Client，而不是仅 warning 后继续。

### 6. 审计安全性

普通日志不足以作为审计证据。

需要增强：

- 审计记录追加写，避免覆盖。
- 每条审计记录计算 hash。
- 可选实现链式 hash：`record_hash = sha256(prev_hash || record_json)`。
- 审计接口返回记录 hash，便于证明记录未被篡改。
- 安全失败事件单独标记：验签失败、票据过期、重放、身份不匹配、解密失败。

### 7. V WebUI 与 Client Logs 区分

当前 Client `/api/logs` 更像通信包抓包视图；堡垒机审计应以 V 端为准。

需要明确两类日志：

- Client Logs：展示 AS/TGS/V 通信封包，辅助调试协议。
- V Audit Logs：展示认证结果、PTY 输入输出、会话回放，作为审计依据。

前端可以保留现有 Client Logs，同时新增或完善 V Audit 页面。


## 建议实施顺序

1. 新增 V 端 SQLite 审计存储和数据结构。
2. 在 V 的 AP_REQ、APP_REQ、PTY output、close/error 路径写审计记录。
3. 实现 `/api/auth_log`、`/api/pty_log`、`/api/audit/session/:id`。
4. 补 Client 对 APP_REP 的 V 签名校验。
5. 强制执行 Client/V 证书校验。
6. 做最小会话回放页面。
7. 增加审计相关自动化测试。

## 完成标准

- 使用 `CLIENT_1/password` 登录后，可以在 V 审计接口查到完整认证记录。
- 打开终端、输入命令、看到输出、关闭会话后，可以在 V 审计接口查到完整 PTY 帧记录。
- 即使会话已关闭，历史审计记录仍可查询。
- Client 能拒绝 V 签名错误的 APP_REP。
- V 能拒绝 Client 签名错误或证书无效的 APP_REQ。
- V WebUI 或 Client WebUI 至少有一个页面能查看会话审计和回放。
