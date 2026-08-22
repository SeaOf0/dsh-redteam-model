# dsh-campaign-memory (战役记忆)

九模式的跨会话战役记忆——把打过的仗变成可召回的打法资产，置于「AttackAtlas」标签页左侧。

- 沉淀：模型侧 `campaign_memory_write` 随战随记（tactic 战术打法 / fingerprint 目标指纹 / tooling 工具可用性 / lesson 教训 / detect 检测指纹）。存储原文不做脱敏——内网地址与指纹细节是打法价值所在；凭据不入记忆是纪律而非转换：凭据单独存本地凭据库（hunter key 库 / webshell 连接库等），记忆只写指位，需要时从库读。
- 召回：`campaign_memory_search` 检索即记账（usage_count / last_used_at 自增）；装配上下文自动携带该模式高频记忆（`<dsh-campaign-memory>` 标记块——与 route-boost 信封同款结构化标记，上下文压缩后仍可识别）。
- 生命周期：detect（检测指纹）类默认 30 天过期（免杀情报半衰期），其余默认永久；可 `expires_days` 自定义；过期自动退出召回，支持一键清理。
- 治理：`campaign_memory_list` / `campaign_memory_remove` 保持记忆库可信；Web 标签页「战役记忆」九模式浏览 / 检索 / 全文 / 删除 / 过期清理。

模型侧工具：`campaign_memory_write`、`campaign_memory_search`、`campaign_memory_list`、`campaign_memory_remove`。存储 `~/.dsh/campaign-memory/memory.db`，模式作用域（跨会话长期资产）。HTTP 通道 `/dsh-campaign-memory/`（memory.list / search / write / remove / stats / purge），同源信任栅栏。

测试：`node test/run.mjs`
