# README

项目设计文档以 `/docs` 下最新文档为准

V 服务端的本地配置不纳入 Git。首次运行时，从仓库根目录复制不含 SSH 目标登录信息的样例；已有本地配置时无需重复复制。

PowerShell：

```powershell
if (!(Test-Path -LiteralPath verify_server/config.json)) {
    Copy-Item -LiteralPath verify_server/config.jump.sample.json -Destination verify_server/config.json
}
```

Linux / macOS：

```bash
cp -n verify_server/config.jump.sample.json verify_server/config.json
```

然后从仓库根目录启动 V 服务端：

```bash
go run ./verify_server/cmd --config verify_server/config.json
```

SSH 目标的真实主机地址、用户名和密码通过 V 管理界面配置，保存在本地审计数据库中。请勿将本地配置、数据库、日志或构建缓存加入 Git；文档中的 SSH 登录信息仅使用占位符。
