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
| `portunus.mcp.config` | 查看或设置暴露策略 `policy`、危险指令处置 `confirm` 与工具列法 `surface`（写入需确认） |
| `portunus.mcp.schema` | 查看指令投影成的 MCP 工具形态 |
| `portunus.mcp.parse` | 调试：把 JSON `arguments` 反向组装成指令文本 |

模块作者关心的「你的指令怎么变成 MCP 工具」见 [现行约定](./b-Office/现行约定.md)；`portunus.*` 各条的参数读注册自描述：`diana.docs.read domain=portunus`（宿主 6.1.0 起没有消费文档）。

## 入口

| 入口 | 用途 |
| --- | --- |
| [`AGENTS.md`](./AGENTS.md) | AI 工作合同：读取顺序、真值判定、边界 |
| [`project.manifest.json`](./project.manifest.json) | 项目身份、活动目录、文档与命令 |
| [现行约定](./b-Office/现行约定.md) | 唯一的长期文档：真相在哪、取舍、已知缺口、工程约定 |

## 目录

| 路径 | 职责 |
| --- | --- |
| `b-Code-Portunus/` | 模块源码、manifest 与 `eng/` 构建脚本 |
| `b-Code-Verify/` | `Contracts` 合同测试 |
| `b-Office/` | `current/现行约定.md`，仅此一份 |
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

- **客户端每次调用前重读 `%APPDATA%\HistoryVulcan\ModuleData\HistoryPortunus\endpoint.json`。** Web 令牌随每一轮模块热重载换发，缓存令牌下一次重载就会 401；文件不存在即此刻没有 Web 入口。
- `vulcan.module.install` / `reload` 会拆掉正在服务它们的监听器：客户端看到断连（约 1 秒），指令本身已成功。应重读 endpoint 再查询确认，不要当成失败。
- 设置在 `%APPDATA%\HistoryVulcan\ModuleData\HistoryPortunus\state\portunus-settings.json`：`mcp.autostart` / `web.autostart` 控制自启动，端口固定、占用即失败不漂移。
- 它坏了不影响修复自己：把好包拷进 `%APPDATA%\HistoryVulcan\Modules\HistoryPortunus`，宿主文件监视会自己重载。
- 部署包不携带任何 `HistoryVulcan.*.dll`；热重载要求 `Dispose` 时关闭 `HttpListener`，否则旧监听器继续占端口。

## 保留内容

### logo与作者

- 作者：pinavia
- ![logo](./Logo.png)

### 学习许可与权利保留

- 本项目允许个人、学校和研究者进行非商业性的学习、研究和引用。
- 未经著作权人书面许可，不得将项目内容用于商业开发、产品制造、商业服务、商业宣传、投标交付、毕业设计成品交付或再授权。
- 不得删除作者、来源、版本历史和第三方许可证声明，不得将本项目或其衍生成果宣称为与作者无关的原创项目。
- 软件源码适用 [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)；机械模型、PCB、原理图、图片、文档、Unity 工程和其他非软件资料适用 [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/)。
- SE、SW、STEP/STP 及其他三维模型仅允许个人或学校进行非商业学习、评审和研究；未经著作权人书面许可，不得用于加工、打样、制造、销售、量产、投标、产品交付、商业宣传、改作或再授权。
- 第三方组件、模板、元件库、外购件模型和工具仍受其原始许可证约束；本声明不扩大作者对第三方内容的权利。

商业使用、产品化、公司内部长期使用、转让或排他性授权需另行取得著作权人的书面许可。
