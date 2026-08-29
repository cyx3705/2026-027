# HistoryPortunus 1.0 消费说明

Portunus 1.0 只支持 HistoryVulcan 5.1+。模块运行时只使用宿主 `HistoryVulcan.Core` 的命令总线与命令注册器；不得引用宿主源码工程、`HistoryVulcan.Extensibility.dll` 或历史 MCP 类型。

Web 客户端在每次调用前读取 `%AppData%\\HistoryVulcan\\service\\endpoint.json`，并以其中的 `accessToken` 作为 Bearer 凭据。MCP 只服务本机回环：不校验令牌。Cursor 用户配置 `%USERPROFILE%\\.cursor\\mcp.json` 的 `history-vulcan` 由模块在监听成功后写入 `url=http://127.0.0.1:<mcp.port>/mcp`，不要加 `headers.Authorization`。
