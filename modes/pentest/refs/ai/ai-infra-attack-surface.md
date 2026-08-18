---
name: ai-infra-attack-surface
description: >
  AI 基础设施组件的攻击面：向量数据库（Milvus 认证绕过三洞 + 拖库语义）、LLM 网关
  （LiteLLM guardrail SSRF）、AI 应用框架（Langflow 双 RCE）、RAG 底座的数据泄露特殊性
  （向量+原文配套存储、相似度检索可恢复内容）。2026 社区系列提炼。
domain: cybersecurity
subdomain: ai-security
tags: [ai-infra, milvus, vector-database, llm-gateway, rag, litellm, langflow]
version: 1.0.0
---

# AI 基础设施攻击面（2026）

> 背景：RAG 是 2026 年 AI 应用标配，其底座（向量数据库/LLM 网关/编排框架）大量随教程部署、
> 默认配置裸奔。本文件收「AI 底座组件」作为**目标**的攻击面（AI 应用自身漏洞见同目录其他文件）。

## 1. 向量数据库（Milvus 实战三洞）

**指纹**：19530（gRPC 固定 banner）、9091 `/healthz` 返回 OK——可测绘特征明确。

| 攻击面 | 利用条件 | 权限 | 修复版本 |
|---|---|---|---|
| sourceid 后门（19530） | 端口可达 | full admin | 2.6.5 |
| 9091 管理端口 /expr 弱 token | 端口可达 | 任意表达式求值 | 2.6.10 |
| 内部端口 53100 无认证 | 容器网络内 | full admin | 2.6.10（不再监听） |

- sourceid 后门：认证拦截器给内部组件留的通道——请求头 `sourceid: base64(@@milvus-member@@)`
  即跳过全部认证（硬编码，等效于给所有摸到端口的人开 full admin）；
- 教程部署通病：`authorizationEnabled` 默认 false（裸奔）、root/Milvus 默认密码、compose 把
  19530+9091 全映射公网。

## 2. 拖库语义：向量库 ≠ 普通数据库

- RAG 场景**向量与原文配套存储**——拖库即拖走整个知识库明文（企业文档/客服记录/内部知识）；
- 即使无原文，**相似度检索本身可恢复内容**（查相邻向量捞回相近文本）——对知识库场景「内容透明」；
- 报告定性建议：向量库失陷按「企业文档资产全量泄露」口径评估影响，高于同级别的普通数据库。

## 3. LLM 网关与编排框架

- LiteLLM：guardrail 相关接口存在 SSRF（`xz.aliyun.com/news/92632`）——**AI 运行时的扩展能力边界**
  （guardrail/路由/模型热加载都接受配置型输入）是 SSRF/RCE 富矿；
- Langflow 1.9.0：两个 CVSS 9.6 RCE（`forum.butian.net/share/4968`）——可视化编排的「节点即代码」
  模式使低权限编辑等同代码执行；
- 通用判据：AI 网关/编排器的**管理面**（模型配置/guardrail/管道定义）暴露即高危——它们本质是
  「远程注入运行时行为」的接口。

## 4. 打点建议（渗透工作流挂点）

- 资产测绘阶段：AI 组件指纹单列（Milvus 19530/9091、Ollama 11434、LiteLLM 4000、Langflow 7860、
  n8n 5678）——Shodan internetdb 可直接出 cpe；
- 打点顺序：管理端口（9091 类弱 token/无认证）> 数据端口后门头（sourceid 类）> 默认凭证；
- 拿下后动作与 cloud-postexploitation 衔接（CAM/AK 类凭据扩线）。

## 来源

- [先知 — 一个请求头拿下 Milvus 集群](https://xz.aliyun.com/news/92652)
- [先知 — 从 LiteLLM Guardrail SSRF 看 AI 运行时扩展能力边界](https://xz.aliyun.com/news/92632)
- [奇安信攻防社区 — Langflow 1.9.0 连环雷：两个 CVSS 9.6 的 RCE](https://forum.butian.net/share/4968)
