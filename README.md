# HistoryPortunus

体系的**对外传输**。把 HistoryVulcan 的指令注册表投影给进程外的消费者，自己不产生任何业务能力。

Portunus 是罗马的钥匙、门户与港口之神。它在 1.0 中完整持有对外传输：宿主只提供权威命令总线，
Portunus 负责将其投影为 Web 与 MCP，并在模块内以默认拒绝的策略控制外部可见性。

## 装了几条航线

| 航线 | 状态 | 服务对象 |
|---|---|---|
| Web | 1.0 | 回环 HTTP：`/api/health`、`/api/commands`、`/api/command` |
| MCP | 1.0 | agent（Claude Code / Cursor 等）按 MCP 协议调用指令 |

两者共享回环绑定、会话身份和对总线的执行，所以合成一个模块而不是两个——
拆开要付两份 manifest 与发布，换来的隔离却是假的：它们编译到同一份宿主快照，
宿主 API 一动一起坏。Web 仍对前端持券；MCP 对本机 agent 不持券。

## 客户端契约

### 1.0.5 本机 MCP 不持券

Portunus 1.0.5 随宿主启动自动开启 MCP 与回环 Web。默认固定端口为 MCP `8777`、Web `8938`，两者只绑定 `127.0.0.1`，端口被占用时不会自动换端口。
MCP 不校验 Bearer。监听成功后把 `%USERPROFILE%\\.cursor\\mcp.json` 的 `history-vulcan` 写成当前 url，并去掉鉴权头——带 `Authorization` 时 Cursor 会走 `mcp_auth`，工具发现失败。
配置保存在 `%APPDATA%\\HistoryVulcan\\state\\portunus-settings.json`：`mcp.autostart` / `web.autostart` 控制自启动，`mcp.port` / `web.port` 固定端口；将任一自启动键设为 `false` 可关闭对应监听。默认 `mcp.policy=standard`。


**每次调用前重读 `%APPDATA%\HistoryVulcan\service\endpoint.json`。**

Web 请求同时需要 `Authorization: Bearer <accessToken>` 与 `X-HistoryVulcan-Client: Shell`。
只发送 Bearer 仍会返回 401。健康检查使用 `GET /api/health`，命令目录使用
`GET /api/commands`，执行命令使用 `POST /api/command`，JSON 为 `{"text":"vulcan.module.list"}`。

它由本模块独占：启动成功后写入，`Dispose` 时删除。里面的 `accessToken` 是**本次监听**的
一次性凭据，而本模块随宿主的每一轮模块热重载重启，所以令牌的换发频率是「每次重载」，
不是「每次宿主启动」。把令牌缓存在客户端进程里，下一次重载就会拿到 401。

文件不存在 = 本机此刻没有可用的 Web 入口。这是如实的，不是异常。

### 会触发模块重载的指令拿不到响应

`vulcan.module.install`、`vulcan.module.reload` 这类指令**会拆掉正在服务它们的监听器**，
客户端看到的是连接被关闭，而指令本身已经执行成功。

这不是缺陷，是传输住在被重载的快照里的必然结果。断开窗口约 1 秒。
客户端应当：重读 endpoint.json → 重试查询确认结果，而不是把断连当成失败。

## 它坏掉的时候

**不影响修复自己。** 把好包拷进 `%APPDATA%\HistoryVulcan\Modules\HistoryPortunus`，
宿主的文件监视会自己重载——恢复路径是文件系统，不是传输。

代价只有两条，都可降级：查活状态改读日志，解文件锁改停服起服。

## 对宿主的硬性要求

`MinimumHistoryVulcanVersion = 5.1.0`。Portunus 1.0 只支持 HistoryVulcan 5.1 及以上的发布快照：

5.1 将模块公开面收敛为命令总线和命令注册器，并从宿主移除了 MCP/schema/client 的领域类型。
Portunus 因此自行持有传输实现、MCP 投影策略与持久配置；它不再引用宿主源码工程或已删除的
`HistoryVulcan.Extensibility.dll`。部署包仍不携带任何 `HistoryVulcan.*.dll`，运行时只使用宿主提供的
Core 公开面。

热重载仍要求宿主在拆除阶段 `Dispose` 模块实例。模块持有 `HttpListener`，必须在旧快照
卸载前关闭监听器；否则旧监听器会继续占端口并保留权威命令总线引用。

## 迁移背景

Portunus 1.0 不再依赖历史宿主的 MCP/Extensibility 程序集。它只引用宿主的发布快照
`HistoryVulcan.Core.dll` 与 `HistoryVulcan.Services.dll`，且这些引用在模块包中保持 `Private=false`。
