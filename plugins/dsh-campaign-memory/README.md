# dsh-campaign-memory (战役记忆)

九模式的跨会话战役记忆——把打过的仗变成可召回的打法资产；Web 端为独立的「战役记忆」会话标签页。治理核心：token 可控前提下的记忆完整。

- 沉淀：模型侧 `campaign_memory_write` 随战随记（tactic 战术打法 / fingerprint 目标指纹 / tooling 工具可用性 / lesson 教训 / detect 检测指纹）。存储原文不做脱敏——内网地址与指纹细节是打法价值所在，凭据同样原样入库（记忆库是本地库）；已有独立凭据库（hunter key 库 / webshell 连接库等）时也可只写指位，需要时从库读。同模式同工作区同题写入=刷新既有记忆（正文与时效更新、热度保留，不产生重复）；**刷新带回执**（原正文字数与开头预览——非同题误合并可察觉）；正文建议四段结构（命中条件/打法步骤/关键参数/验证结果），超 4000 字符**显式截断**（返回 truncated 提示，不静默腰斩）。
- 召回：`campaign_memory_search` 检索预览不记账，`campaign_memory_get` 读全文即记账（usage_count / last_used_at 刷新）；检索走 **FTS5 trigram**——多关键词空格分词 OR 召回（词分离也能命中）、bm25×热度混排（词法更贴者排前）、命中窗摘录（snippet 环绕最佳命中，token 收敛；短词 LIKE 补位、FTS 不可用回落整串 LIKE）；排序=使用热度×30 天时间衰减——久未读取的记忆自然让位、读取即复活，早期记忆不再永久霸占召回位。装配上下文自动携带该模式本工作区高频记忆（`<dsh-campaign-memory>` 标记块——与 route-boost 信封同款结构化标记，上下文压缩后仍可识别）。
- 生命周期：detect（检测指纹）默认 30 天过期并自动清理（免杀情报半衰期）；fingerprint（目标指纹）默认 180 天——到期退出自动召回，但检索仍可命中（带过期标记）、同题重写即刷新时效；其余默认永久；可 `expires_days` 自定义。工作区超 400 条冷淘汰（热度×半衰最旧让位），**淘汰行归档 `memories_archive` 可恢复**。
- 治理：`campaign_memory_list` / `campaign_memory_remove` 保持记忆库可信；「清理过期」只清过期检测指纹，其余到期记忆保留资产（含已过期视图查看/取舍）；Web 标签页「战役记忆」九模式浏览 / 检索 / 全文 / 删除。经验沉淀归途唯一：跨任务可复用经验（lessons）以本库为准，工作区 `lessons.md` 仅收随目录交接的执行便签（见 shared 技能 ecosystem-cooperation「经验台账」）。

模型侧工具：`campaign_memory_write`、`campaign_memory_search`、`campaign_memory_get`、`campaign_memory_list`、`campaign_memory_remove`。存储 `~/.dsh/campaign-memory/memory.db`（旧库开库自动重建 FTS 索引，热度/时效无损），模式作用域（跨会话长期资产）。HTTP 通道 `/dsh-campaign-memory/`（memory.list / search / get / write / remove / stats / purge），同源信任栅栏 + CSRF。

测试：`node test/run.mjs`
