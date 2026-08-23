# dsh-campaign-memory (战役记忆)

九模式的跨会话战役记忆——把打过的仗变成可召回的打法资产，置于「AttackAtlas」标签页左侧。

- 沉淀：模型侧 `campaign_memory_write` 随战随记（tactic 战术打法 / fingerprint 目标指纹 / tooling 工具可用性 / lesson 教训 / detect 检测指纹）。存储原文不做脱敏——内网地址与指纹细节是打法价值所在，凭据同样原样入库（记忆库是本地库）；已有独立凭据库（hunter key 库 / webshell 连接库等）时也可只写指位，需要时从库读。同模式同工作区同题写入=刷新既有记忆（正文与时效更新、热度保留，不产生重复）。
- 召回：`campaign_memory_search` 检索预览不记账，`campaign_memory_get` 读全文即记账（usage_count / last_used_at 刷新）；排序=使用热度×30 天时间衰减——久未读取的记忆自然让位、读取即复活，早期记忆不再永久霸占召回位。装配上下文自动携带该模式本工作区高频记忆（`<dsh-campaign-memory>` 标记块——与 route-boost 信封同款结构化标记，上下文压缩后仍可识别）。
- 生命周期：detect（检测指纹）默认 30 天过期并自动清理（免杀情报半衰期）；fingerprint（目标指纹）默认 180 天——到期退出自动召回，但检索仍可命中（带过期标记）、同题重写即刷新时效；其余默认永久；可 `expires_days` 自定义。
- 治理：`campaign_memory_list` / `campaign_memory_remove` 保持记忆库可信；「清理过期」只清过期检测指纹，其余到期记忆保留资产（含已过期视图查看/取舍）；Web 标签页「战役记忆」九模式浏览 / 检索 / 全文 / 删除。

模型侧工具：`campaign_memory_write`、`campaign_memory_search`、`campaign_memory_list`、`campaign_memory_remove`。存储 `~/.dsh/campaign-memory/memory.db`，模式作用域（跨会话长期资产）。HTTP 通道 `/dsh-campaign-memory/`（memory.list / search / write / remove / stats / purge），同源信任栅栏。

测试：`node test/run.mjs`
