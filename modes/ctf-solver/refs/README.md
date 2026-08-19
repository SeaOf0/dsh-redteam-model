# CTF 解题知识库索引

> 知识库按模块组织（共 118 篇，MIT 许可证随附见 `LICENSE`）。
> 读取纪律：grep/本索引先行 → read 带 offset/limit 按节读，禁止整本 read；题目无关模块不加载。
> `solve-challenge/` 是分诊入口（题型不明确时先读它做 triage 与路由），其余按模块进。

| 模块 | 篇数 | 目录 | 覆盖 |
|---|---|---|---|
| web | 21 | `ctf-web/` | SQLi/XSS/SSTI/SSRF/XXE/JWT/请求走私/OAuth·SAML/原型污染/上传/前端与身份流 |
| pwn | 19 | `ctf-pwn/` | 栈溢出与 ROP/格式化字符串/堆利用（fsop 等）/内核与容器逃逸/高级利用系列/实战笔记 |
| reverse | 19 | `ctf-reverse/` | 静态动态逆向/反调试/壳/VM 与字节码/sourcemap 还原/算法还原 |
| crypto | 17 | `ctf-crypto/` | 古典与编码/分组密码/RSA/椭圆曲线/格/哈希与签名/攻击模型 |
| forensics | 15 | `ctf-forensics/` | 磁盘恢复与进阶/内存/网络流量/浏览器与邮箱/时间线 |
| misc | 13 | `ctf-misc/` | 隐写（图像/音频/媒体）/压缩包/自定义协议与重放/杂项 |
| ai-ml | 4 | `ctf-ai-ml/` | 模型与推理攻击/提示注入类题 |
| osint | 4 | `ctf-osint/` | 情报检索类题 |
| malware | 4 | `ctf-malware/` | 恶意样本类题 |
| writeup | 1 | `ctf-writeup/` | 解题报告写法 |
| 分诊入口 | 1 | `solve-challenge/` | 题型 triage 与模块路由 |

跨模块补充（生态加载，不在本库）：AD/域 → attack-defense 与 binary-analysis refs；云/K8s →
cloud-security refs；mobile 逆向 → binary-analysis mobile refs。
