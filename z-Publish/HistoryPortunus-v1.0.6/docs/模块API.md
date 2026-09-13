# HistoryPortunus 模块 API

模块版本：**1.0.5**；最低宿主：**HistoryVulcan 5.1**。

本文件是**总线面**合同。代码面（服务实现、反向解析、Schema 生成）在
`b-Office/current/技术合同.md`；AI 面就是本模块**产出**的那一层，不在这里描述。

## 这个模块提供什么

Portunus 把宿主的指令面投影成 MCP 工具，对本机回环提供 MCP 服务。
它是**别的模块的 AI 面得以存在的那一层**——不是别的模块该调用的东西。

指令域 `portunus`，共 6 条，**全部声明了 `HiddenReason`**（防止远程递归管理或关闭 MCP 服务）：
它们不投影成 MCP 工具、也不能经 `HistoryVulcan.Cli.exe --runtime` 执行，
只能在本机控制台或界面里调。**跨模块不要调 `portunus.*`**。

| 指令 | 参数 | 说明 |
| --- | --- | --- |
| `portunus.mcp.status` | — | 运行状态、端口、策略、暴露工具数、累计调用、最近一次调用 |
| `portunus.mcp.start` | `port` | 启动服务（仅 `127.0.0.1`），并自动对齐 Cursor `mcp.json` |
| `portunus.mcp.stop` | — | 停止服务并释放端口 |
| `portunus.mcp.autostart` | `enabled` | 查看或设置随宿主自动监听（持久化；省略 `enabled` 只查看） |
| `portunus.mcp.schema` | `name` | 查看指令的 MCP 工具形态；不带参列全部，带 `name` 输出单条完整 JSON Schema |
| `portunus.mcp.parse` | `command`、`args`、`exec` | 调试：把 JSON `arguments` 反向组装成指令文本，`exec=true` 随即经总线执行 |

## 模块作者要知道的：你的指令怎么变成 MCP 工具

只有 `Readonly == true && HiddenReason == null` 的指令会被投影。所以：

- 想让 AI 能用你的能力，**给它一条只读、不隐藏的指令**，参数用 `ParameterSpec` 声明清楚——
  `Description` 会进 JSON Schema，那就是 AI 唯一能读到的说明。
- 不想让 AI 碰的，声明 `HiddenReason`，写清为什么。
- 工具名是指令名把 `.` 换成 `_`（`minerva.plan.package` → `minerva_plan_package`）。
- 拿不准自己的指令投影成什么样，跑 `portunus.mcp.schema name=<指令名>`。

`module.manifest.json` 的 `mcpExposure` 决定本模块整体是否参与投影。

## 端口与凭据

MCP 只服务本机回环，**不校验令牌**。

Web 客户端每次调用前读 `%AppData%\HistoryVulcan\service\endpoint.json`，
以其中的 `accessToken` 作 Bearer 凭据——那是 Web 面，不是 MCP 面，别混。

Cursor 的 `%USERPROFILE%\.cursor\mcp.json` 里的 `history-vulcan` 由本模块在监听成功后写入
`url=http://127.0.0.1:<mcp.port>/mcp`，**不要加 `headers.Authorization`**。

**端口是会变的**：别把端口写死在任何配置或脚本里，用 `portunus.mcp.status` 问。

## 宿主要求

模块运行时只使用宿主 `HistoryVulcan.Core` 的命令总线与命令注册器；
不得引用宿主源码工程、`HistoryVulcan.Extensibility.dll`（5.0 已删）或历史 MCP 类型。

## 1.0.6 参数保真

MCP 字符串参数按原文传递给命令处理器，中文、换行及字面量反斜杠转义保持区分。命令文本使用宿主 QuoteArg 编码，调用方不应额外转义 Unicode。
