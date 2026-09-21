# HistoryPortunus

> 对外传输模块：把宿主指令总线投影为本机 MCP 与回环 Web

## 定位

HistoryPortunus 把 HistoryVulcan 的指令注册表投影给进程外的消费者，自己不产生任何业务能力。
名字取自罗马的钥匙、门户与港口之神。

- 宿主只提供权威命令总线；Web 与 MCP 两条传输、外部可见性策略（默认拒绝）、会话与设置都由本模块持有。
- 两条传输共享回环绑定、会话身份和总线执行，所以合成一个模块：拆开要付两份 manifest 与发布，隔离却是假的。
- 它是别的模块的 AI 面得以存在的那一层，**不是别的模块该调用的东西**。

## 概况

| 项 | 值 |
| --- | --- |
| 编号 | `2026-027` |
| 角色 | 宿主模块（`kind=module`） |
| 指令域 | `portunus`（全部带 `HiddenReason`，不进 MCP、不能经 `--runtime` 执行） |
| 界面 | 无（`ui: false`） |
| 传输 | MCP `127.0.0.1:8777`（不持券）；Web `127.0.0.1:8938`（Bearer + 客户端头） |
| 版本与宿主下限 | [`PortunusVersion.props`](./b-Code-Portunus/PortunusVersion.props) |

## 能力

| 指令 | 用途 |
| --- | --- |
| `portunus.mcp.status` | 运行状态、端口、策略、暴露工具数与最近调用 |
| `portunus.mcp.start` / `stop` | 启停 MCP 服务，启动时对齐 Cursor `mcp.json` |
| `portunus.mcp.autostart` | 查看或设置随宿主自动监听 |
| `portunus.mcp.schema` | 查看指令投影成的 MCP 工具形态 |
| `portunus.mcp.parse` | 调试：把 JSON `arguments` 反向组装成指令文本 |

模块作者关心的「你的指令怎么变成 MCP 工具」见 [模块 API](./b-Office/package/模块API.md)。

## 入口

| 入口 | 用途 |
| --- | --- |
| [`AGENTS.md`](./AGENTS.md) | AI 工作合同：读取顺序、真值判定、边界 |
| [`project.manifest.json`](./project.manifest.json) | 项目身份、活动目录、文档与命令 |
| [文档中心](./b-Office/文档中心.md) | 文档索引与读取顺序 |
| [项目概览](./b-Office/current/项目概览.md) | 目标、范围与状态 |
| [技术合同](./b-Office/current/技术合同.md) | 现行需求与架构 |
| [有效决策](./b-Office/current/有效决策.md) | 仍然有效的关键决策 |
| [验证合同](./b-Office/current/验证合同.md) | 验证层级、命令与证据 |
| [模块 API](./b-Office/package/模块API.md) | 跨模块消费合同 |

## 目录

| 路径 | 职责 |
| --- | --- |
| `b-Code-Portunus/` | 模块源码、manifest 与 `eng/` 构建脚本 |
| `b-Code-Verify/` | `Contracts` 合同测试 |
| `b-Office/` | 项目文档：`current/` 现行合同、`package/` 消费合同、`history/` 只读归档 |
| `z-Publish/` | 正式快照与 `history/` 归档，由宿主管线写入 |

## 构建与验证

```powershell
dotnet restore .\HistoryPortunus.sln --locked-mode -p:NuGetAudit=false
dotnet build .\HistoryPortunus.sln -c Release --no-restore -p:NuGetAudit=false
dotnet test .\b-Code-Verify\Contracts\Contracts.csproj -c Release -p:NuGetAudit=false
```

## 开发与发布

改动只进 `vulcan.dev.start` 创建的工作区，经宿主 Console CLI 走
`vulcan.dev.start` → `vulcan.dev.submit`（候选构建并热装送审）→ `vulcan.dev.finish`（批准后并回并写入 `z-Publish`）。
本仓不自行发布。

## 要点

- **客户端每次调用前重读 `%APPDATA%\HistoryVulcan\service\endpoint.json`。** Web 令牌随每一轮模块热重载换发，缓存令牌下一次重载就会 401；文件不存在即此刻没有 Web 入口。
- `vulcan.module.install` / `reload` 会拆掉正在服务它们的监听器：客户端看到断连（约 1 秒），指令本身已成功。应重读 endpoint 再查询确认，不要当成失败。
- 设置在 `%APPDATA%\HistoryVulcan\state\portunus-settings.json`：`mcp.autostart` / `web.autostart` 控制自启动，端口固定、占用即失败不漂移。
- 它坏了不影响修复自己：把好包拷进 `%APPDATA%\HistoryVulcan\Modules\HistoryPortunus`，宿主文件监视会自己重载。
- 部署包不携带任何 `HistoryVulcan.*.dll`；热重载要求 `Dispose` 时关闭 `HttpListener`，否则旧监听器继续占端口。

## 保留内容
- 本模板项目介绍：此为最初的准备的项目模板
    每个分支项目都会由他去继承
- 作者：Pinavia - 2025

![logo](./Logo.png)
