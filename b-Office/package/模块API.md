# HistoryPortunus 1.0 消费说明

Portunus 1.0 只支持 HistoryVulcan 5.1+。模块运行时只使用宿主 `HistoryVulcan.Core` 的命令总线与命令注册器；不得引用宿主源码工程、`HistoryVulcan.Extensibility.dll` 或历史 MCP 类型。

Web 客户端在每次调用前读取 `%AppData%\\HistoryVulcan\\service\\endpoint.json`，连接其 `port` 指定的本机回环端口。每次请求必须同时携带 `Authorization: Bearer <accessToken>` 和 `X-HistoryVulcan-Client: Shell`；缺少任一项均返回 401。可选的 `X-Session-Id` 和 `X-Client-Name` 用于标识客户端会话。接口为 `GET /api/health`、`GET /api/commands` 和 `POST /api/command`，命令请求 JSON 为 `{"text":"vulcan.module.list"}`。根路径 `/` 不是健康检查接口。

MCP 只服务本机回环：不校验令牌。Cursor 用户配置 `%USERPROFILE%\\.cursor\\mcp.json` 的 `history-vulcan` 由模块在监听成功后写入 `url=http://127.0.0.1:<mcp.port>/mcp`，不要加 `headers.Authorization`。
