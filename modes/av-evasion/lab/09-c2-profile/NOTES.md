# C2 流量与行为定制

- 技术/配置侧（四件套，已补全于 malleable.profile）：
  ① 业务 JSON 包裹——http-get 完整输出链（base64url + prepend/append + print 终止），
     任务命令藏在 items[].v 业务字段；http-post 上行结果塞 evt 字段，确认回执走 ack 字段；
  ② JA3 一致化——UA 与 TLS 栈同生态匹配三原则注释块（SChannel 风格栈/密码套件顺序
     /扩展与 ALPN 对齐），UA 声称的客户端生态必须与 ClientHello 指纹一致；
  ③ 心跳抖动——sleep 60s + jitter ±20%（实际 48~72s 窗口），http-post 心跳节
     （空闲期零上行，结果与心跳语义合并）；
  ④ 分段外带——chunk 语义伪指令（chunk_mode/chunk_size/chunk_param：大结果按块切片、
     单块 4KB 对齐业务事件包、分片序号伪装业务分页字段）。
- 进阶（注释块）：域前置变体——连接域与 Host 头分离（TLS 连 CDN 边缘节点、Host 指向
  被前置业务域）；附"证书同颁/SNI 一致性校验封禁"注意事项。
- 检测侧配对：JA3+HTTP2 指纹组合库比对（TLS 栈与 UA 生态不一致即穿帮）；beacon 周期性
  统计检测（低抖动心跳聚类）；响应包络与业务基线偏离（异常字段结构/包体积）；已知
  profile 特征（开源配置复用=指纹，sample_name 同源回溯）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 验证记录：malleable.profile 为研究配置非可执行物，本机无 c2lint/Cobalt Strike 环境，
  语法校验未执行（如实标注）；配置逻辑已人工走查（http-get/post 输出链完整、四件套
  与域前置注释块齐备）。
