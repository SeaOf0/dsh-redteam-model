#!/usr/bin/env python3
"""
深度测试引擎工具 (v2.1 - Burp Suite级别交互能力)

从 mcp_server.py setup_mcp_server() 提取
条件注册: 需要 DEEP_TEST_ENGINE_AVAILABLE = True
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

try:
    from deep_test_engine import HTTPInteractionEngine, ResponseAnalyzer, DynamicFuzzer
    _DEEP_TEST_IMPORT_OK = True
except Exception:
    HTTPInteractionEngine = None
    ResponseAnalyzer = None
    DynamicFuzzer = None
    _DEEP_TEST_IMPORT_OK = False


def register_deep_test_tools(mcp, executor, DEEP_TEST_ENGINE_AVAILABLE):
    """深度测试引擎工具注册 (条件注册)"""

    # ==================== 深度测试引擎工具 (v2.1 - Burp Suite级别) ====================
    if DEEP_TEST_ENGINE_AVAILABLE and _DEEP_TEST_IMPORT_OK:
        try:
            # 初始化引擎实例
            _http_engine = HTTPInteractionEngine()
            _analyzer = ResponseAnalyzer()
            _fuzzer = DynamicFuzzer(_http_engine, _analyzer)

            logger.info(" 注册深度测试引擎工具...")

            # ==================== HTTP 交互工具 (6个) ====================

            @mcp.tool()
            async def http_send(
                url: str,
                method: str = "GET",
                headers: str = "{}",
                body: str = "",
                cookies: str = "{}",
                follow_redirects: bool = True,
                timeout: float = 30.0
            ) -> Dict[str, Any]:
                """
                发送自定义HTTP请求 - 类Burp Suite Repeater功能

                Args:
                    url: 目标URL
                    method: HTTP方法 (GET/POST/PUT/DELETE/PATCH)
                    headers: JSON格式的自定义请求头
                    body: 请求体内容
                    cookies: JSON格式的Cookie
                    follow_redirects: 是否跟随重定向
                    timeout: 超时时间(秒)

                Returns:
                    完整HTTP响应，包含状态码、头部、body、时间等
                """
                try:
                    import json as json_module
                    headers_dict = json_module.loads(headers) if headers and headers != "{}" else {}
                    cookies_dict = json_module.loads(cookies) if cookies and cookies != "{}" else {}
                    body_bytes = body.encode('utf-8') if body else None

                    response = await _http_engine.send_request(
                        url=url,
                        method=method,
                        headers=headers_dict,
                        body=body_bytes,
                        cookies=cookies_dict,
                        follow_redirects=follow_redirects,
                        timeout=timeout
                    )

                    return {
                        "success": True,
                        "request_id": response.id,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:10000] if len(response.text) > 10000 else response.text,
                        "body_length": len(response.body),
                        "cookies": response.cookies,
                        "elapsed_time_ms": response.elapsed_time,
                        "final_url": response.final_url,
                        "redirect_count": response.redirect_count,
                        "message": f"HTTP {method} 请求成功 - {response.status_code}"
                    }
                except Exception as e:
                    logger.error(f"HTTP请求失败: {e}")
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def http_replay(
                request_id: str,
                modifications: str = "{}"
            ) -> Dict[str, Any]:
                """
                重放历史HTTP请求，可修改参数

                Args:
                    request_id: 要重放的请求ID
                    modifications: JSON格式的修改项 {"url": "...", "headers": {...}, "body": "..."}

                Returns:
                    重放后的HTTP响应
                """
                try:
                    import json as json_module
                    mods = json_module.loads(modifications) if modifications and modifications != "{}" else {}
                    response = await _http_engine.replay_request(request_id, mods)

                    if response:
                        return {
                            "success": True,
                            "original_request_id": request_id,
                            "new_request_id": response.id,
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "body": response.text[:10000],
                            "elapsed_time_ms": response.elapsed_time,
                            "modifications_applied": mods,
                            "message": "请求重放成功"
                        }
                    return {"success": False, "error": "请求不存在或重放失败"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def http_send_raw(
                raw_request: str,
                host: str,
                port: int = 443,
                use_ssl: bool = True
            ) -> Dict[str, Any]:
                """
                发送原始HTTP请求 - 完全控制请求格式

                Args:
                    raw_request: 原始HTTP请求文本 (包含请求行、头部、body)
                    host: 目标主机
                    port: 目标端口
                    use_ssl: 是否使用SSL

                Returns:
                    原始HTTP响应
                """
                try:
                    response = await _http_engine.send_raw_request(
                        raw_request.encode('utf-8'),
                        host,
                        port,
                        use_ssl
                    )

                    if response:
                        return {
                            "success": True,
                            "request_id": response.id,
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "body": response.text[:10000],
                            "raw_response_preview": response.raw[:2000].decode('utf-8', errors='replace'),
                            "elapsed_time_ms": response.elapsed_time,
                            "message": "原始请求发送成功"
                        }
                    return {"success": False, "error": "发送失败"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def http_history(
                filter_url: str = "",
                filter_status: int = 0,
                limit: int = 50
            ) -> Dict[str, Any]:
                """
                查看HTTP请求历史

                Args:
                    filter_url: URL过滤（包含匹配）
                    filter_status: 状态码过滤（0表示不过滤）
                    limit: 返回数量限制

                Returns:
                    请求历史列表
                """
                try:
                    history = _http_engine.get_history(
                        filter_url=filter_url if filter_url else None,
                        filter_status=filter_status if filter_status > 0 else None,
                        limit=limit
                    )

                    history_list = []
                    for req, resp in history:
                        history_list.append({
                            "request_id": req.id,
                            "url": req.url,
                            "method": req.method,
                            "status_code": resp.status_code if resp else None,
                            "elapsed_time_ms": resp.elapsed_time if resp else None,
                            "timestamp": req.timestamp.isoformat()
                        })

                    return {
                        "success": True,
                        "total_count": len(history_list),
                        "history": history_list,
                        "message": f"返回 {len(history_list)} 条请求历史"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def http_compare(
                request_id_1: str,
                request_id_2: str
            ) -> Dict[str, Any]:
                """
                比较两个HTTP响应的差异 - 用于盲注检测

                Args:
                    request_id_1: 第一个请求ID
                    request_id_2: 第二个请求ID

                Returns:
                    详细的差异分析
                """
                try:
                    history = {req.id: (req, resp) for req, resp in _http_engine.history}

                    if request_id_1 not in history or request_id_2 not in history:
                        return {"success": False, "error": "请求ID不存在"}

                    _, resp1 = history[request_id_1]
                    _, resp2 = history[request_id_2]

                    # 分析差异
                    status_diff = resp1.status_code != resp2.status_code
                    time_diff = abs(resp1.elapsed_time - resp2.elapsed_time)
                    length_diff = abs(len(resp1.body) - len(resp2.body))

                    # 内容差异分析
                    content_similarity = _calculate_content_similarity(resp1.text, resp2.text)

                    # 检测盲注指标
                    blind_injection_indicators = []
                    if time_diff > 3000:  # 3秒时间差
                        blind_injection_indicators.append("time_based_injection_possible")
                    if length_diff > 100:
                        blind_injection_indicators.append("boolean_based_injection_possible")
                    if status_diff:
                        blind_injection_indicators.append("status_difference_detected")

                    return {
                        "success": True,
                        "comparison": {
                            "status_code_diff": status_diff,
                            "response1_status": resp1.status_code,
                            "response2_status": resp2.status_code,
                            "time_diff_ms": time_diff,
                            "response1_time_ms": resp1.elapsed_time,
                            "response2_time_ms": resp2.elapsed_time,
                            "length_diff_bytes": length_diff,
                            "response1_length": len(resp1.body),
                            "response2_length": len(resp2.body),
                            "content_similarity": content_similarity
                        },
                        "blind_injection_indicators": blind_injection_indicators,
                        "analysis": {
                            "likely_vulnerable": len(blind_injection_indicators) > 0,
                            "confidence": len(blind_injection_indicators) / 3.0
                        },
                        "message": f"响应比较完成 - 相似度: {content_similarity:.2%}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            def _calculate_content_similarity(text1: str, text2: str) -> float:
                """计算两个文本的相似度"""
                if not text1 or not text2:
                    return 0.0
                if text1 == text2:
                    return 1.0
                # 简单的Jaccard相似度
                set1 = set(text1.split())
                set2 = set(text2.split())
                intersection = len(set1 & set2)
                union = len(set1 | set2)
                return intersection / union if union > 0 else 0.0

            @mcp.tool()
            async def http_session_manage(
                action: str,
                session_name: str = "default",
                cookies: str = "{}",
                tokens: str = "{}"
            ) -> Dict[str, Any]:
                """
                管理HTTP会话 - Cookie和Token管理

                Args:
                    action: 操作类型 (create/get/update/delete/list)
                    session_name: 会话名称
                    cookies: JSON格式的Cookie
                    tokens: JSON格式的Token (Authorization等)

                Returns:
                    会话管理结果
                """
                try:
                    import json as json_module
                    cookies_dict = json_module.loads(cookies) if cookies and cookies != "{}" else {}
                    tokens_dict = json_module.loads(tokens) if tokens and tokens != "{}" else {}

                    if action == "create":
                        _http_engine.create_session(session_name, cookies_dict, tokens_dict)
                        return {"success": True, "action": "created", "session": session_name}
                    elif action == "get":
                        session = _http_engine.get_session(session_name)
                        return {"success": True, "session": session}
                    elif action == "update":
                        _http_engine.update_session(session_name, cookies_dict, tokens_dict)
                        return {"success": True, "action": "updated", "session": session_name}
                    elif action == "delete":
                        _http_engine.delete_session(session_name)
                        return {"success": True, "action": "deleted", "session": session_name}
                    elif action == "list":
                        sessions = _http_engine.list_sessions()
                        return {"success": True, "sessions": sessions}
                    else:
                        return {"success": False, "error": f"未知操作: {action}"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== 响应分析工具 (4个) ====================

            @mcp.tool()
            async def analyze_response(
                response_id: str = "",
                response_body: str = "",
                response_headers: str = "{}"
            ) -> Dict[str, Any]:
                """
                深度响应分析 - 漏洞指标检测

                Args:
                    response_id: 历史响应ID (优先使用)
                    response_body: 响应体文本 (如果没有response_id)
                    response_headers: JSON格式响应头

                Returns:
                    详细的安全分析结果
                """
                try:
                    import json as json_module

                    if response_id:
                        # 从历史获取响应
                        history = {req.id: (req, resp) for req, resp in _http_engine.history}
                        if response_id in history:
                            _, resp = history[response_id]
                            response_body = resp.text
                            response_headers = json_module.dumps(dict(resp.headers))

                    headers_dict = json_module.loads(response_headers) if response_headers and response_headers != "{}" else {}

                    # 执行分析
                    analysis = _analyzer.analyze_response(response_body, headers_dict)

                    return {
                        "success": True,
                        "vulnerability_indicators": analysis.get("vulnerability_indicators", []),
                        "information_disclosure": analysis.get("information_disclosure", []),
                        "technology_fingerprints": analysis.get("technology_fingerprints", []),
                        "security_headers_analysis": analysis.get("security_headers", {}),
                        "sensitive_data_found": analysis.get("sensitive_data", []),
                        "recommended_tests": analysis.get("recommended_tests", []),
                        "risk_level": analysis.get("risk_level", "unknown"),
                        "message": f"响应分析完成 - 发现 {len(analysis.get('vulnerability_indicators', []))} 个漏洞指标"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def detect_blind_vulnerability(
                baseline_request_id: str,
                test_request_id: str,
                injection_type: str = "sql"
            ) -> Dict[str, Any]:
                """
                盲注漏洞检测 - 基于响应差异

                Args:
                    baseline_request_id: 基准请求ID (正常请求)
                    test_request_id: 测试请求ID (注入payload后)
                    injection_type: 注入类型 (sql/cmd/xpath)

                Returns:
                    盲注检测结果
                """
                try:
                    history = {req.id: (req, resp) for req, resp in _http_engine.history}

                    if baseline_request_id not in history or test_request_id not in history:
                        return {"success": False, "error": "请求ID不存在"}

                    _, baseline = history[baseline_request_id]
                    _, test_resp = history[test_request_id]

                    result = _analyzer.detect_blind_vulnerability(
                        baseline, test_resp, injection_type
                    )

                    return {
                        "success": True,
                        "injection_type": injection_type,
                        "vulnerable": result.get("vulnerable", False),
                        "confidence": result.get("confidence", 0),
                        "detection_method": result.get("method", "unknown"),
                        "evidence": result.get("evidence", {}),
                        "time_difference_ms": result.get("time_diff", 0),
                        "content_difference": result.get("content_diff", 0),
                        "recommended_payloads": result.get("next_payloads", []),
                        "message": f"盲注检测完成 - {'可能存在漏洞' if result.get('vulnerable') else '未检测到漏洞'}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def fingerprint_target(
                url: str
            ) -> Dict[str, Any]:
                """
                目标技术指纹识别

                Args:
                    url: 目标URL

                Returns:
                    技术栈指纹信息
                """
                try:
                    # 发送请求获取响应
                    response = await _http_engine.send_request(url)

                    # 分析技术指纹
                    fingerprint = _analyzer.fingerprint_technology(response)

                    return {
                        "success": True,
                        "url": url,
                        "fingerprint": {
                            "web_server": fingerprint.get("server", "unknown"),
                            "programming_language": fingerprint.get("language", "unknown"),
                            "framework": fingerprint.get("framework", "unknown"),
                            "cms": fingerprint.get("cms", "unknown"),
                            "waf_detected": fingerprint.get("waf", None),
                            "cdn_detected": fingerprint.get("cdn", None),
                            "os_hints": fingerprint.get("os", "unknown"),
                            "headers_analysis": fingerprint.get("headers", {}),
                            "confidence": fingerprint.get("confidence", 0)
                        },
                        "vulnerability_suggestions": fingerprint.get("vuln_suggestions", []),
                        "recommended_tools": fingerprint.get("recommended_tools", []),
                        "message": f"技术指纹识别完成 - {fingerprint.get('server', 'unknown')}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def extract_endpoints(
                response_id: str = "",
                response_body: str = ""
            ) -> Dict[str, Any]:
                """
                从响应中提取端点和API路径

                Args:
                    response_id: 历史响应ID
                    response_body: 响应体文本

                Returns:
                    发现的端点列表
                """
                try:
                    if response_id:
                        history = {req.id: (req, resp) for req, resp in _http_engine.history}
                        if response_id in history:
                            _, resp = history[response_id]
                            response_body = resp.text

                    endpoints = _analyzer.extract_endpoints(response_body)

                    return {
                        "success": True,
                        "endpoints": {
                            "urls": endpoints.get("urls", []),
                            "api_paths": endpoints.get("api_paths", []),
                            "parameters": endpoints.get("parameters", []),
                            "forms": endpoints.get("forms", []),
                            "javascript_endpoints": endpoints.get("js_endpoints", [])
                        },
                        "total_found": sum(len(v) for v in endpoints.values()),
                        "message": f"发现 {sum(len(v) for v in endpoints.values())} 个端点"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== 动态测试工具 (5个) ====================

            @mcp.tool()
            async def adaptive_sqli_test(
                url: str,
                parameter: str,
                method: str = "GET",
                body_template: str = ""
            ) -> Dict[str, Any]:
                """
                自适应SQL注入测试 - 智能检测和利用

                Args:
                    url: 目标URL
                    parameter: 测试参数名
                    method: HTTP方法
                    body_template: POST请求体模板 (用{PAYLOAD}标记注入点)

                Returns:
                    SQL注入测试结果
                """
                try:
                    result = await _fuzzer.adaptive_sql_injection(
                        url, parameter, method, body_template
                    )

                    return {
                        "success": True,
                        "vulnerable": result.get("vulnerable", False),
                        "injection_type": result.get("injection_type", "unknown"),
                        "database_type": result.get("database_type", "unknown"),
                        "payload_used": result.get("poc_payload", ""),
                        "evidence": result.get("evidence", {}),
                        "extracted_data": result.get("extracted_data", None),
                        "confidence": result.get("confidence", 0),
                        "test_statistics": {
                            "payloads_tested": result.get("payloads_tested", 0),
                            "successful_payloads": result.get("successful_payloads", 0),
                            "time_taken_seconds": result.get("time_taken", 0)
                        },
                        "poc": result.get("poc", ""),
                        "message": f"SQL注入测试完成 - {'发现漏洞!' if result.get('vulnerable') else '未发现漏洞'}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def adaptive_xss_test(
                url: str,
                parameter: str,
                context: str = "auto"
            ) -> Dict[str, Any]:
                """
                自适应XSS测试 - 上下文感知的XSS检测

                Args:
                    url: 目标URL
                    parameter: 测试参数名
                    context: XSS上下文 (auto/html/attribute/javascript/url)

                Returns:
                    XSS测试结果
                """
                try:
                    result = await _fuzzer.adaptive_xss_test(url, parameter, context)

                    return {
                        "success": True,
                        "vulnerable": result.get("vulnerable", False),
                        "xss_type": result.get("xss_type", "unknown"),
                        "context_detected": result.get("context", "unknown"),
                        "payload_used": result.get("poc_payload", ""),
                        "reflection_found": result.get("reflection", False),
                        "encoding_bypass": result.get("encoding_bypass", None),
                        "filter_bypass": result.get("filter_bypass", None),
                        "confidence": result.get("confidence", 0),
                        "poc": result.get("poc", ""),
                        "message": f"XSS测试完成 - {'发现漏洞!' if result.get('vulnerable') else '未发现漏洞'}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def adaptive_cmdi_test(
                url: str,
                parameter: str,
                os_type: str = "auto"
            ) -> Dict[str, Any]:
                """
                自适应命令注入测试

                Args:
                    url: 目标URL
                    parameter: 测试参数名
                    os_type: 操作系统类型 (auto/linux/windows)

                Returns:
                    命令注入测试结果
                """
                try:
                    result = await _fuzzer.adaptive_command_injection(url, parameter, os_type)

                    return {
                        "success": True,
                        "vulnerable": result.get("vulnerable", False),
                        "injection_type": result.get("injection_type", "unknown"),
                        "os_detected": result.get("os_type", "unknown"),
                        "payload_used": result.get("poc_payload", ""),
                        "command_output": result.get("output", ""),
                        "blind_injection": result.get("blind", False),
                        "confidence": result.get("confidence", 0),
                        "poc": result.get("poc", ""),
                        "message": f"命令注入测试完成 - {'发现漏洞!' if result.get('vulnerable') else '未发现漏洞'}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def fuzz_parameter(
                url: str,
                parameter: str,
                payload_type: str = "all",
                method: str = "GET",
                body_template: str = ""
            ) -> Dict[str, Any]:
                """
                参数模糊测试 - 发送多种Payload测试参数

                Args:
                    url: 目标URL
                    parameter: 测试参数名
                    payload_type: Payload类型 (all/sqli/xss/cmdi/lfi/ssti)
                    method: HTTP方法
                    body_template: POST请求体模板

                Returns:
                    模糊测试结果
                """
                try:
                    result = await _fuzzer.fuzz_parameter(
                        url, parameter, payload_type, method, body_template
                    )

                    return {
                        "success": True,
                        "parameter": parameter,
                        "payload_type": payload_type,
                        "total_payloads": result.get("total_tested", 0),
                        "interesting_responses": result.get("interesting", []),
                        "potential_vulnerabilities": result.get("vulnerabilities", []),
                        "errors_triggered": result.get("errors", []),
                        "recommendations": result.get("recommendations", []),
                        "message": f"模糊测试完成 - 发现 {len(result.get('vulnerabilities', []))} 个潜在漏洞"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def fuzz_all_params(
                url: str,
                method: str = "GET",
                body: str = "",
                test_types: str = "sqli,xss,cmdi,lfi"
            ) -> Dict[str, Any]:
                """
                全参数模糊测试 - 自动识别并测试所有参数

                Args:
                    url: 目标URL
                    method: HTTP方法
                    body: 请求体 (用于POST)
                    test_types: 测试类型，逗号分隔

                Returns:
                    所有参数的测试结果
                """
                try:
                    types = [t.strip() for t in test_types.split(",")]
                    result = await _fuzzer.fuzz_all_parameters(url, method, body, types)

                    return {
                        "success": True,
                        "url": url,
                        "parameters_found": result.get("parameters", []),
                        "parameters_tested": result.get("tested_count", 0),
                        "vulnerabilities_found": result.get("vulnerabilities", []),
                        "vulnerability_summary": result.get("summary", {}),
                        "highest_risk": result.get("highest_risk", "none"),
                        "recommendations": result.get("recommendations", []),
                        "poc_scripts": result.get("poc_scripts", []),
                        "message": f"全参数测试完成 - 发现 {len(result.get('vulnerabilities', []))} 个漏洞"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== WebSocket 工具 (3个) ====================

            @mcp.tool()
            async def ws_connect(
                url: str,
                headers: str = "{}"
            ) -> Dict[str, Any]:
                """
                建立WebSocket连接

                Args:
                    url: WebSocket URL (ws:// 或 wss://)
                    headers: JSON格式的自定义头

                Returns:
                    连接ID和状态
                """
                try:
                    from deep_test_engine import WebSocketEngine
                    import json as json_module

                    global _ws_engine
                    if '_ws_engine' not in globals():
                        _ws_engine = WebSocketEngine()

                    headers_dict = json_module.loads(headers) if headers and headers != "{}" else {}
                    connection_id = await _ws_engine.connect(url, headers_dict)

                    return {
                        "success": True,
                        "connection_id": connection_id,
                        "url": url,
                        "status": "connected",
                        "message": f"WebSocket连接成功 - ID: {connection_id}"
                    }
                except ImportError:
                    return {"success": False, "error": "WebSocket引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def ws_send(
                connection_id: str,
                message: str,
                message_type: str = "text",
                wait_response: bool = True,
                timeout: float = 10.0
            ) -> Dict[str, Any]:
                """
                发送WebSocket消息

                Args:
                    connection_id: 连接ID
                    message: 消息内容
                    message_type: 消息类型 (text/binary)
                    wait_response: 是否等待响应
                    timeout: 响应超时(秒)

                Returns:
                    发送结果和响应
                """
                try:
                    from deep_test_engine import WebSocketEngine

                    global _ws_engine
                    if '_ws_engine' not in globals():
                        return {"success": False, "error": "没有活跃的WebSocket连接"}

                    sent = await _ws_engine.send_message(connection_id, message, message_type)

                    result = {
                        "success": True,
                        "sent": sent.to_dict(),
                        "message": "消息发送成功"
                    }

                    if wait_response:
                        received = await _ws_engine.receive_message(connection_id, timeout)
                        if received:
                            result["response"] = received.to_dict()
                            result["response_text"] = received.text

                    return result
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def ws_fuzz(
                connection_id: str,
                payloads: str,
                analyze: bool = True
            ) -> Dict[str, Any]:
                """
                WebSocket模糊测试

                Args:
                    connection_id: 连接ID
                    payloads: JSON数组格式的Payload列表
                    analyze: 是否分析响应

                Returns:
                    模糊测试结果
                """
                try:
                    from deep_test_engine import WebSocketEngine
                    import json as json_module

                    global _ws_engine
                    if '_ws_engine' not in globals():
                        return {"success": False, "error": "没有活跃的WebSocket连接"}

                    payload_list = json_module.loads(payloads)
                    results = await _ws_engine.fuzz_websocket(connection_id, payload_list, analyze)

                    interesting = [r for r in results if r.get("analysis", {}).get("interesting")]

                    return {
                        "success": True,
                        "total_payloads": len(payload_list),
                        "responses_received": len([r for r in results if r.get("received")]),
                        "interesting_responses": len(interesting),
                        "results": results,
                        "potential_vulnerabilities": [r for r in interesting if r.get("analysis", {}).get("indicators")],
                        "message": f"WebSocket模糊测试完成 - {len(interesting)} 个有趣响应"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== gRPC 工具 (2个) ====================

            @mcp.tool()
            async def grpc_reflect(
                host: str,
                port: int,
                use_ssl: bool = False
            ) -> Dict[str, Any]:
                """
                gRPC服务反射 - 获取服务定义

                Args:
                    host: gRPC服务主机
                    port: gRPC服务端口
                    use_ssl: 是否使用SSL

                Returns:
                    服务和方法列表
                """
                try:
                    from deep_test_engine import GRPCEngine

                    grpc_engine = GRPCEngine()
                    result = await grpc_engine.reflect_services(host, port, use_ssl)

                    return {
                        "success": result.get("success", False),
                        "services": result.get("services", []),
                        "methods": result.get("methods", {}),
                        "total_services": len(result.get("services", [])),
                        "total_methods": sum(len(m) for m in result.get("methods", {}).values()),
                        "error": result.get("error"),
                        "message": f"发现 {len(result.get('services', []))} 个gRPC服务"
                    }
                except ImportError:
                    return {"success": False, "error": "gRPC引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def grpc_call(
                host: str,
                port: int,
                service: str,
                method: str,
                request_data: str,
                use_ssl: bool = False
            ) -> Dict[str, Any]:
                """
                调用gRPC方法

                Args:
                    host: gRPC服务主机
                    port: gRPC服务端口
                    service: 服务名
                    method: 方法名
                    request_data: JSON格式的请求数据
                    use_ssl: 是否使用SSL

                Returns:
                    gRPC调用结果
                """
                try:
                    from deep_test_engine import GRPCEngine
                    import json as json_module

                    grpc_engine = GRPCEngine()
                    data = json_module.loads(request_data)
                    call = await grpc_engine.call_method(host, port, service, method, data, use_ssl)

                    return {
                        "success": call.status_code == 0,
                        "service": service,
                        "method": method,
                        "status_code": call.status_code,
                        "status_message": call.status_message,
                        "response_data": call.response_data,
                        "elapsed_time_ms": call.elapsed_time,
                        "message": f"gRPC调用完成 - {call.status_message}"
                    }
                except ImportError:
                    return {"success": False, "error": "gRPC引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== 代理拦截工具 (3个) ====================

            @mcp.tool()
            async def proxy_start(
                listen_port: int = 8080,
                listen_host: str = "127.0.0.1"
            ) -> Dict[str, Any]:
                """
                启动代理服务器 - 用于流量拦截

                Args:
                    listen_port: 监听端口
                    listen_host: 监听地址

                Returns:
                    代理启动状态
                """
                try:
                    from deep_test_engine import ProxyInterceptor

                    global _proxy
                    _proxy = ProxyInterceptor(listen_host, listen_port)
                    result = await _proxy.start()

                    return {
                        "success": result.get("success", False),
                        "proxy_url": f"http://{listen_host}:{listen_port}",
                        "ca_cert_path": result.get("ca_cert"),
                        "status": "running" if result.get("success") else "failed",
                        "message": f"代理服务器启动于 {listen_host}:{listen_port}"
                    }
                except ImportError:
                    return {"success": False, "error": "代理模块未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def proxy_add_rule(
                rule_type: str,
                url_pattern: str = "",
                method: str = "",
                action: str = "",
                params: str = "{}"
            ) -> Dict[str, Any]:
                """
                添加代理规则 - 拦截或修改请求

                Args:
                    rule_type: 规则类型 (intercept/modify)
                    url_pattern: URL匹配模式
                    method: HTTP方法过滤
                    action: 动作 (对于modify: replace/add_header/modify_body)
                    params: JSON格式的规则参数

                Returns:
                    规则添加结果
                """
                try:
                    import json as json_module

                    global _proxy
                    if '_proxy' not in globals():
                        return {"success": False, "error": "代理未启动"}

                    params_dict = json_module.loads(params) if params and params != "{}" else {}

                    if rule_type == "intercept":
                        rule_id = _proxy.add_intercept_rule(url_pattern, method)
                    elif rule_type == "modify":
                        rule_id = _proxy.add_modify_rule(
                            url_pattern, action,
                            params_dict.get("target", ""),
                            params_dict.get("value", "")
                        )
                    else:
                        return {"success": False, "error": f"未知规则类型: {rule_type}"}

                    return {
                        "success": True,
                        "rule_id": rule_id,
                        "rule_type": rule_type,
                        "url_pattern": url_pattern,
                        "message": f"规则添加成功 - ID: {rule_id}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def proxy_get_intercepted() -> Dict[str, Any]:
                """
                获取已拦截的请求列表

                Returns:
                    拦截的请求列表
                """
                try:
                    global _proxy
                    if '_proxy' not in globals():
                        return {"success": False, "error": "代理未启动"}

                    intercepted = _proxy.get_intercepted_requests()

                    requests_list = []
                    for req_id, req in intercepted.items():
                        requests_list.append({
                            "request_id": req_id,
                            "url": req.url,
                            "method": req.method,
                            "timestamp": req.timestamp.isoformat(),
                            "status": req.status
                        })

                    return {
                        "success": True,
                        "total_intercepted": len(requests_list),
                        "requests": requests_list,
                        "message": f"共 {len(requests_list)} 个拦截请求"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== 工作流工具 (3个) ====================

            @mcp.tool()
            async def workflow_define(
                name: str,
                steps: str,
                description: str = ""
            ) -> Dict[str, Any]:
                """
                定义测试工作流

                Args:
                    name: 工作流名称
                    steps: JSON数组格式的步骤定义
                    description: 工作流描述

                Returns:
                    工作流定义结果
                """
                try:
                    from deep_test_engine import WorkflowEngine
                    import json as json_module

                    global _workflow_engine
                    if '_workflow_engine' not in globals():
                        _workflow_engine = WorkflowEngine(_http_engine)

                    steps_list = json_module.loads(steps)
                    workflow_id = _workflow_engine.define_workflow(name, steps_list, description)

                    return {
                        "success": True,
                        "workflow_id": workflow_id,
                        "name": name,
                        "steps_count": len(steps_list),
                        "message": f"工作流 '{name}' 定义成功"
                    }
                except ImportError:
                    return {"success": False, "error": "工作流引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def workflow_execute(
                workflow_id: str,
                initial_vars: str = "{}"
            ) -> Dict[str, Any]:
                """
                执行测试工作流

                Args:
                    workflow_id: 工作流ID或内置工作流名称
                    initial_vars: JSON格式的初始变量

                Returns:
                    工作流执行结果
                """
                try:
                    from deep_test_engine import WorkflowEngine
                    import json as json_module

                    global _workflow_engine
                    if '_workflow_engine' not in globals():
                        _workflow_engine = WorkflowEngine(_http_engine)

                    vars_dict = json_module.loads(initial_vars) if initial_vars and initial_vars != "{}" else {}
                    result = await _workflow_engine.execute_workflow(workflow_id, vars_dict)

                    return {
                        "success": result.get("success", False),
                        "workflow_id": workflow_id,
                        "steps_executed": result.get("steps_executed", 0),
                        "steps_successful": result.get("steps_successful", 0),
                        "final_state": result.get("final_state", "unknown"),
                        "variables": result.get("variables", {}),
                        "step_results": result.get("step_results", []),
                        "findings": result.get("findings", []),
                        "message": f"工作流执行完成 - {result.get('final_state', 'unknown')}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def auth_bypass_test(
                login_url: str,
                protected_url: str,
                credentials: str = "{}"
            ) -> Dict[str, Any]:
                """
                认证绕过测试 - 内置工作流

                Args:
                    login_url: 登录页面URL
                    protected_url: 受保护资源URL
                    credentials: JSON格式的凭据 {"username": "...", "password": "..."}

                Returns:
                    认证绕过测试结果
                """
                try:
                    from deep_test_engine import WorkflowEngine
                    import json as json_module

                    global _workflow_engine
                    if '_workflow_engine' not in globals():
                        _workflow_engine = WorkflowEngine(_http_engine)

                    creds = json_module.loads(credentials) if credentials and credentials != "{}" else {}
                    result = await _workflow_engine.execute_auth_bypass_test(login_url, protected_url, creds)

                    return {
                        "success": True,
                        "bypass_found": result.get("bypass_found", False),
                        "bypass_methods": result.get("bypass_methods", []),
                        "tested_techniques": result.get("techniques_tested", []),
                        "successful_bypasses": result.get("successful_bypasses", []),
                        "session_analysis": result.get("session_analysis", {}),
                        "recommendations": result.get("recommendations", []),
                        "message": f"认证绕过测试完成 - {'发现绕过方法!' if result.get('bypass_found') else '未发现绕过'}"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}

            # ==================== 学习引擎工具 (2个) ====================

            @mcp.tool()
            async def get_recommended_payloads(
                test_type: str,
                target_url: str,
                limit: int = 10
            ) -> Dict[str, Any]:
                """
                获取推荐的Payload - 基于历史数据和目标特征

                Args:
                    test_type: 测试类型 (sqli/xss/cmdi/lfi/ssti)
                    target_url: 目标URL
                    limit: 返回数量

                Returns:
                    推荐的Payload列表
                """
                try:
                    from deep_test_engine import LearningEngine

                    global _learning_engine
                    if '_learning_engine' not in globals():
                        _learning_engine = LearningEngine()

                    # 获取目标指纹
                    response = await _http_engine.send_request(target_url)
                    fingerprint = _analyzer.fingerprint_technology(response)

                    # 获取推荐
                    payloads = _learning_engine.get_recommended_payloads(test_type, fingerprint, limit)

                    return {
                        "success": True,
                        "test_type": test_type,
                        "target_fingerprint": fingerprint,
                        "recommended_payloads": payloads,
                        "total_recommendations": len(payloads),
                        "confidence_scores": [p.get("confidence", 0) for p in payloads],
                        "message": f"推荐 {len(payloads)} 个 {test_type} Payload"
                    }
                except ImportError:
                    return {"success": False, "error": "学习引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            @mcp.tool()
            async def get_attack_strategy(
                target_url: str
            ) -> Dict[str, Any]:
                """
                获取攻击策略推荐 - 基于历史成功率

                Args:
                    target_url: 目标URL

                Returns:
                    推荐的攻击策略
                """
                try:
                    from deep_test_engine import LearningEngine

                    global _learning_engine
                    if '_learning_engine' not in globals():
                        _learning_engine = LearningEngine()

                    # 获取目标指纹
                    response = await _http_engine.send_request(target_url)
                    fingerprint = _analyzer.fingerprint_technology(response)

                    # 获取策略
                    strategy = _learning_engine.get_attack_strategy(fingerprint)

                    return {
                        "success": True,
                        "target_url": target_url,
                        "target_fingerprint": fingerprint,
                        "recommended_strategy": strategy.get("strategy", "unknown"),
                        "attack_priority": strategy.get("priority", []),
                        "expected_success_rate": strategy.get("success_rate", 0),
                        "similar_targets_found": strategy.get("similar_count", 0),
                        "historical_findings": strategy.get("historical_findings", []),
                        "tool_recommendations": strategy.get("tools", []),
                        "message": f"策略推荐: {strategy.get('strategy', 'unknown')}"
                    }
                except ImportError:
                    return {"success": False, "error": "学习引擎未安装"}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            logger.info(" 深度测试引擎 28 个MCP工具注册成功")

        except Exception as e:
            logger.warning(f" 深度测试引擎工具注册失败: {e}")
    else:
        logger.info("ℹ 深度测试引擎不可用，跳过相关工具注册")
