# 任务：exc0.top + Portunus 暴露 MCP — 该升级哪个项目？

## 目标
让云端 Grok Bot 能通过用户自有域名 `exc0.top`（经 Portunus）访问 HistoryVulcan MCP。先**决定升级哪个仓库**，再给最小升级方案。先别大改代码，除非一个小脚手架/文档明显必要。

## 三个候选（本机均有）
1. `C:\OneHistory\HistoryClio\2026-027-HistoryPortunus` → https://github.com/cyx3705/2026-027
   - 外传模块：把命令总线投影为本地 MCP / Web
   - 已安装：`%APPDATA%\HistoryVulcan\Modules\HistoryPortunus`
   - 现况：mcp `127.0.0.1:8777`、web `8938`、autostart true、policy standard；MCP initialize+Bearer 成功（HistoryVulcan 6.1.1）
2. `C:\OneHistory\HistoryClio\2026-023-HistoryVulcan` → https://github.com/cyx3705/2026-023
   - 宿主；MCP 对外面在 Portunus 模块里
3. `C:\OneHistory\HistoryClio\2026-031-OneHistorySite` → https://github.com/cyx3705/2026-031
   - GitHub Pages 目录站，CNAME `onehistory.exc0.top`，静态站，不是反代

## 架构共识（用户已确认）
- 容器化服务上云；宿主保持消费机、无状态、无长期核心数据
- 云端仍是服务模块；本机可有薄转发模块把云 API 投成本地命令
- 不要用临时公网隧道当首选；要自有域名 + Portunus

## DNS 观察
- `exc0.top` 当前解析到 GitHub Pages anycast；Pages 不能直接当 MCP 源站

## 交付
1. 明确主升级项目（可写「Portunus 为主 + 小改 DNS/Vulcan」）
2. 说明 031 要不要动
3. 域名暴露最小设计（子域、DNS/源站、鉴权保持 Bearer）
4. 有序下一步

结论写在对话里；需要改代码时在对应仓库开分支/草稿 PR。
