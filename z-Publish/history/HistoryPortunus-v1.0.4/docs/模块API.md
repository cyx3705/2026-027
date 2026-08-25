# HistoryPortunus 1.0 消费说明

Portunus 1.0 只支持 HistoryVulcan 5.1+。模块运行时只使用宿主 `HistoryVulcan.Core` 的命令总线与命令注册器；不得引用宿主源码工程、`HistoryVulcan.Extensibility.dll` 或历史 MCP 类型。

Web 客户端在每次调用前读取 `%AppData%\\HistoryVulcan\\service\\endpoint.json`，并以其中的 `accessToken` 作为 Bearer 凭据。MCP 客户端从 `portunus.mcp.start` 配置并连接本机 `/mcp` 端点。
