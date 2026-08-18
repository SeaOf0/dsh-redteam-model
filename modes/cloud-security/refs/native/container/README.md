# container/ 参考手册（云原生 · 容器）

> 本目录随 cloud-security 预设打包分发，是 `refs/native/container/` 下关于容器攻击面与检测侧
> 的深度手册。所有文件为预设内自包含资源，互相引用只用相对路径，不依赖机器特定路径。
> 路径解析：相对 `refs/native/` 即 `container/`；从 SKILL 侧访问用 `refs/native/container/`。

## 授权立场提醒（先读）

- 本目录属 cloud-security 授权攻防立场：攻击视角默认授权，只读命令优先，破坏性/变更性操作
  先询问，删除操作只出清单由用户确认后执行。
- 每篇利用路径条目都配**检测侧对照**（运行时审计 / 宿主审计 / K8s audit 三层叠加）；
  检测侧情报回馈 attack-defense 与 `detection-gap.md`。
- 破坏性步骤一律标「授权内人工确认后执行」；凭证发现登记后提示轮换。

## 快速路由（按研究类型找文件）

| 研究类型 | 文件 |
|---|---|
| 容器逃逸路径全景（privileged/capabilities/socket/内核/运行时配置） | `01-container-escape-paths.md` |
| 镜像供应链（Dockerfile 缺陷/镜像层泄露/私有仓库未授权） | `02-image-supply-chain.md` |
| 容器网络与运行时安全（seccomp/AppArmor/运行时审计，检测侧） | `03-container-network-runtime-detection.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| 01-container-escape-paths.md | 五类逃逸原语的只读判定、影响分级、检测侧三层对照 | 评估容器→宿主突破时 |
| 02-image-supply-chain.md | 构建期/存储期/分发期供应链缺陷与凭证恢复 | 找镜像内密钥、私有仓库越权时 |
| 03-container-network-runtime-detection.md | seccomp/AppArmor/运行时审计的机制、缺口与事件对照 | 做检测侧评估、写 detection-gap 时 |

## 计数

共 3 篇 md。
