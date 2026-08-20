#!/usr/bin/env python3
"""
浏览器自动化工具 - 反检测浏览器引擎 MCP 工具注册

用于需要JS渲染和心跳维持的现代Web应用渗透测试。
当目标网站使用动态心跳检测、WebSocket保活、JS指纹识别时，
curl/wget 无法维持会话，此模块通过 Playwright + stealth 插件
启动伪装的 Chromium 浏览器完成交互。

从 mcp_server.py setup_mcp_server() 提取
条件注册: 需要 BROWSER_ENGINE_AVAILABLE = True
"""

import logging
import os
import time
import json as json_module
from typing import Dict, Any

logger = logging.getLogger(__name__)

# ==================== 浏览器引擎依赖检测 ====================
try:
    from kali_mcp.core.browser_engine import StealthBrowserEngine, HAS_PLAYWRIGHT
    _BROWSER_IMPORT_OK = True and HAS_PLAYWRIGHT
except Exception:
    StealthBrowserEngine = None
    HAS_PLAYWRIGHT = False
    _BROWSER_IMPORT_OK = False

# ==================== 全局浏览器引擎实例 (延迟初始化) ====================
_browser_engine = None

# 截图保存目录
_SCREENSHOT_DIR = "/tmp/kali_mcp_screenshots"


async def _get_engine():
    """获取或创建全局浏览器引擎实例 (延迟初始化)"""
    global _browser_engine
    if _browser_engine is None:
        from kali_mcp.core.browser_engine import StealthBrowserEngine
        _browser_engine = StealthBrowserEngine()
        await _browser_engine.start()
    return _browser_engine


def register_browser_tools(mcp, executor, BROWSER_ENGINE_AVAILABLE):
    """浏览器自动化工具注册 (条件注册)"""

    if not (BROWSER_ENGINE_AVAILABLE and _BROWSER_IMPORT_OK):
        logger.info("ℹ 浏览器引擎不可用，跳过浏览器工具注册")
        return

    try:
        logger.info(" 注册浏览器自动化工具...")

        # ==================== 1. 会话管理工具 (3个) ====================

        @mcp.tool()
        async def browser_start_session(
            url: str,
            session_id: str = "",
            headless: bool = True,
            proxy: str = "",
            user_agent: str = ""
        ) -> Dict[str, Any]:
            """
            启动反检测浏览器会话 - 用于需要JS渲染和心跳维持的现代Web应用渗透测试

            当目标网站使用动态心跳检测、WebSocket保活、JS指纹识别时，
            curl/wget无法维持会话。此工具启动一个伪装的Chromium浏览器，
            自动通过反检测并维持长期会话。

            Args:
                url: 目标URL
                session_id: 自定义会话ID（默认自动生成）
                headless: 无头模式（默认True，设为False可看到浏览器窗口）
                proxy: 代理地址（如 http://127.0.0.1:8080 用于配合Burp）
                user_agent: 自定义User-Agent（默认自动匹配Chrome版本）

            Returns:
                会话信息：session_id, cookies, page_title, url, heartbeat_status
            """
            try:
                engine = await _get_engine()

                # 构建浏览器启动选项
                options = {}
                if proxy:
                    options["proxy"] = proxy
                if user_agent:
                    options["user_agent"] = user_agent
                options["headless"] = headless

                # 创建浏览器会话
                session = await engine.create_session(
                    session_id=session_id if session_id else None,
                    **options
                )
                sid = session.session_id

                # 导航到目标URL
                await session.navigate(url, wait_until="networkidle")

                # 启动心跳监控
                await session.start_heartbeat_monitor()

                # 获取页面基本信息
                page_title = await session.page.title()
                current_url = session.page.url
                cookies = await session.page.context.cookies()

                # 获取心跳状态
                heartbeat_status = session.get_heartbeat_status() if hasattr(session, "get_heartbeat_status") else {"status": "monitor_started"}

                return {
                    "success": True,
                    "session_id": sid,
                    "page_title": page_title,
                    "current_url": current_url,
                    "cookies": [{"name": c["name"], "value": c["value"], "domain": c.get("domain", "")} for c in cookies],
                    "cookies_count": len(cookies),
                    "heartbeat_status": heartbeat_status,
                    "headless": headless,
                    "proxy": proxy or "none",
                    "message": f"浏览器会话已启动 - {page_title}"
                }
            except Exception as e:
                logger.error(f"启动浏览器会话失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_close_session(
            session_id: str
        ) -> Dict[str, Any]:
            """
            关闭浏览器会话并保存状态（cookies/storage持久化到磁盘）

            Args:
                session_id: 要关闭的会话ID

            Returns:
                关闭结果，包含持久化的cookie和storage信息
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 保存cookies和storage
                cookies = await session.page.context.cookies()
                storage_state = {}
                try:
                    storage_state = await session.page.evaluate("""() => {
                        const ls = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            ls[key] = localStorage.getItem(key);
                        }
                        const ss = {};
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            ss[key] = sessionStorage.getItem(key);
                        }
                        return { localStorage: ls, sessionStorage: ss };
                    }""")
                except Exception:
                    storage_state = {"localStorage": {}, "sessionStorage": {}}

                # 关闭会话
                await engine.close_session(session_id)

                return {
                    "success": True,
                    "session_id": session_id,
                    "cookies_saved": len(cookies),
                    "local_storage_keys": len(storage_state.get("localStorage", {})),
                    "session_storage_keys": len(storage_state.get("sessionStorage", {})),
                    "message": f"浏览器会话已关闭并保存状态 - {len(cookies)} 个cookie"
                }
            except Exception as e:
                logger.error(f"关闭浏览器会话失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_list_sessions() -> Dict[str, Any]:
            """
            列出所有活跃的浏览器会话

            Returns:
                活跃会话列表，包含每个会话的URL、标题和存活时间
            """
            try:
                engine = await _get_engine()
                sessions = engine.list_sessions()

                sessions_info = []
                for sid, session in sessions.items():
                    info = {
                        "session_id": sid,
                        "current_url": session.page.url if session.page else "unknown",
                        "created_at": getattr(session, "created_at", None),
                        "status": "active" if session.page and not session.page.is_closed() else "closed",
                    }
                    # 尝试获取标题
                    try:
                        if session.page and not session.page.is_closed():
                            info["page_title"] = await session.page.title()
                    except Exception:
                        info["page_title"] = "unknown"

                    # 心跳状态
                    if hasattr(session, "get_heartbeat_status"):
                        info["heartbeat_status"] = session.get_heartbeat_status()

                    sessions_info.append(info)

                return {
                    "success": True,
                    "total_sessions": len(sessions_info),
                    "sessions": sessions_info,
                    "message": f"共 {len(sessions_info)} 个活跃浏览器会话"
                }
            except Exception as e:
                logger.error(f"列出浏览器会话失败: {e}")
                return {"success": False, "error": str(e)}

        # ==================== 2. 页面导航与交互工具 (4个) ====================

        @mcp.tool()
        async def browser_navigate(
            session_id: str,
            url: str,
            wait_until: str = "networkidle"
        ) -> Dict[str, Any]:
            """
            在已有会话中导航到新页面

            Args:
                session_id: 会话ID
                url: 目标URL
                wait_until: 等待条件 (load/domcontentloaded/networkidle)

            Returns:
                page_title, current_url, cookies_count, heartbeat_detected
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 导航
                await session.navigate(url, wait_until=wait_until)

                page_title = await session.page.title()
                current_url = session.page.url
                cookies = await session.page.context.cookies()

                # 检查心跳
                heartbeat_detected = False
                if hasattr(session, "get_heartbeat_status"):
                    hb_status = session.get_heartbeat_status()
                    heartbeat_detected = hb_status.get("status") == "active" if isinstance(hb_status, dict) else False

                return {
                    "success": True,
                    "session_id": session_id,
                    "page_title": page_title,
                    "current_url": current_url,
                    "cookies_count": len(cookies),
                    "heartbeat_detected": heartbeat_detected,
                    "message": f"已导航到: {page_title}"
                }
            except Exception as e:
                logger.error(f"浏览器导航失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_click(
            session_id: str,
            selector: str,
            wait_after: int = 1000
        ) -> Dict[str, Any]:
            """
            模拟人工点击页面元素（带随机延迟和鼠标移动模拟）

            适用于需要模拟真实用户交互的场景，如触发按钮、展开菜单等。

            Args:
                session_id: 会话ID
                selector: CSS选择器或XPath (XPath以//开头自动识别)
                wait_after: 点击后等待时间(ms)

            Returns:
                点击结果，包含点击前后的页面URL变化
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                url_before = session.page.url

                # 判断选择器类型
                if selector.startswith("//") or selector.startswith("(//"):
                    # XPath
                    element = session.page.locator(f"xpath={selector}")
                else:
                    # CSS选择器
                    element = session.page.locator(selector)

                # 等待元素可见后点击 (模拟人工行为)
                await element.wait_for(state="visible", timeout=10000)
                await element.click(delay=50)  # 模拟按键延迟

                # 等待点击后效果
                if wait_after > 0:
                    await session.page.wait_for_timeout(wait_after)

                url_after = session.page.url
                page_title = await session.page.title()

                return {
                    "success": True,
                    "session_id": session_id,
                    "selector": selector,
                    "url_before": url_before,
                    "url_after": url_after,
                    "url_changed": url_before != url_after,
                    "page_title": page_title,
                    "message": f"已点击元素: {selector}"
                }
            except Exception as e:
                logger.error(f"浏览器点击失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_type_text(
            session_id: str,
            selector: str,
            text: str,
            delay: int = 80,
            clear_first: bool = True
        ) -> Dict[str, Any]:
            """
            模拟人工输入文本（逐字符输入，随机延迟）

            适用于绕过反自动化的登录表单输入。每个字符之间会添加随机延迟，
            模拟真实用户的打字速度。

            Args:
                session_id: 会话ID
                selector: 输入框的CSS选择器或XPath
                text: 要输入的文本
                delay: 每个字符之间的基础延迟(ms)，实际延迟会有随机波动
                clear_first: 输入前是否先清空输入框（默认True）

            Returns:
                输入结果
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 定位元素
                if selector.startswith("//") or selector.startswith("(//"):
                    element = session.page.locator(f"xpath={selector}")
                else:
                    element = session.page.locator(selector)

                await element.wait_for(state="visible", timeout=10000)

                # 清空输入框
                if clear_first:
                    await element.click()
                    await session.page.keyboard.press("Control+a")
                    await session.page.keyboard.press("Backspace")

                # 逐字符输入 (模拟人工)
                await element.type(text, delay=delay)

                return {
                    "success": True,
                    "session_id": session_id,
                    "selector": selector,
                    "text_length": len(text),
                    "delay_per_char_ms": delay,
                    "cleared_first": clear_first,
                    "message": f"已输入 {len(text)} 个字符到 {selector}"
                }
            except Exception as e:
                logger.error(f"浏览器文本输入失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_execute_js(
            session_id: str,
            script: str
        ) -> Dict[str, Any]:
            """
            在浏览器上下文中执行JavaScript代码

            适用于：提取动态生成的数据、操作DOM、绕过前端验证、
            读取localStorage中的token等。

            Args:
                session_id: 会话ID
                script: 要执行的JavaScript代码

            Returns:
                JavaScript执行结果
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 执行JS
                result = await session.page.evaluate(script)

                # 对结果进行序列化处理
                result_str = None
                if result is not None:
                    try:
                        result_str = json_module.dumps(result, ensure_ascii=False, default=str)
                        # 限制输出长度
                        if len(result_str) > 50000:
                            result_str = result_str[:50000] + "...(truncated)"
                    except (TypeError, ValueError):
                        result_str = str(result)

                return {
                    "success": True,
                    "session_id": session_id,
                    "result": result,
                    "result_preview": result_str[:5000] if result_str else None,
                    "result_type": type(result).__name__ if result is not None else "null",
                    "message": "JavaScript执行成功"
                }
            except Exception as e:
                logger.error(f"JavaScript执行失败: {e}")
                return {"success": False, "error": str(e)}

        # ==================== 3. 数据提取工具 (3个) ====================

        @mcp.tool()
        async def browser_extract_content(
            session_id: str,
            selector: str = "",
            extract_type: str = "text"
        ) -> Dict[str, Any]:
            """
            从渲染后的页面提取数据

            与curl不同，此工具可以提取经过JavaScript渲染后的完整DOM内容，
            包括动态加载的数据。

            Args:
                session_id: 会话ID
                selector: CSS选择器（空=整个页面）
                extract_type: 提取类型 text/html/links/forms/cookies/storage

            Returns:
                根据extract_type返回对应数据
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                page = session.page
                result_data = {}

                if extract_type == "text":
                    if selector:
                        content = await page.locator(selector).inner_text()
                    else:
                        content = await page.inner_text("body")
                    # 限制长度
                    if len(content) > 50000:
                        content = content[:50000] + "\n...(truncated)"
                    result_data = {"text": content, "length": len(content)}

                elif extract_type == "html":
                    if selector:
                        content = await page.locator(selector).inner_html()
                    else:
                        content = await page.content()
                    if len(content) > 100000:
                        content = content[:100000] + "\n...(truncated)"
                    result_data = {"html": content, "length": len(content)}

                elif extract_type == "links":
                    links = await page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                            href: a.href,
                            text: a.innerText.trim().substring(0, 200),
                            target: a.target || '_self'
                        }));
                    }""")
                    result_data = {"links": links, "total": len(links)}

                elif extract_type == "forms":
                    forms = await page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('form')).map((form, idx) => ({
                            id: form.id || `form_${idx}`,
                            action: form.action,
                            method: form.method.toUpperCase(),
                            inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(input => ({
                                name: input.name,
                                type: input.type || 'text',
                                value: input.value,
                                id: input.id,
                                required: input.required
                            }))
                        }));
                    }""")
                    result_data = {"forms": forms, "total": len(forms)}

                elif extract_type == "cookies":
                    cookies = await page.context.cookies()
                    result_data = {
                        "cookies": [
                            {
                                "name": c["name"],
                                "value": c["value"],
                                "domain": c.get("domain", ""),
                                "path": c.get("path", "/"),
                                "httpOnly": c.get("httpOnly", False),
                                "secure": c.get("secure", False),
                                "sameSite": c.get("sameSite", ""),
                                "expires": c.get("expires", -1),
                            }
                            for c in cookies
                        ],
                        "total": len(cookies),
                    }

                elif extract_type == "storage":
                    storage = await page.evaluate("""() => {
                        const ls = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            ls[key] = localStorage.getItem(key);
                        }
                        const ss = {};
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            ss[key] = sessionStorage.getItem(key);
                        }
                        return {
                            localStorage: ls,
                            localStorageCount: Object.keys(ls).length,
                            sessionStorage: ss,
                            sessionStorageCount: Object.keys(ss).length
                        };
                    }""")
                    result_data = storage

                else:
                    return {"success": False, "error": f"不支持的提取类型: {extract_type}，可用: text/html/links/forms/cookies/storage"}

                return {
                    "success": True,
                    "session_id": session_id,
                    "extract_type": extract_type,
                    "selector": selector or "(entire page)",
                    "data": result_data,
                    "message": f"数据提取完成 - 类型: {extract_type}"
                }
            except Exception as e:
                logger.error(f"浏览器数据提取失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_screenshot(
            session_id: str,
            full_page: bool = False,
            selector: str = ""
        ) -> Dict[str, Any]:
            """
            截取页面截图（支持全页面和元素截图）

            截图保存到 /tmp/kali_mcp_screenshots/ 目录。

            Args:
                session_id: 会话ID
                full_page: 是否截取全页面（包括滚动区域）
                selector: 特定元素的CSS选择器（为空则截取视口）

            Returns:
                截图文件路径和尺寸信息
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 确保截图目录存在
                os.makedirs(_SCREENSHOT_DIR, exist_ok=True)

                # 生成文件名
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"screenshot_{session_id}_{timestamp}.png"
                filepath = os.path.join(_SCREENSHOT_DIR, filename)

                if selector:
                    # 元素截图
                    element = session.page.locator(selector)
                    await element.wait_for(state="visible", timeout=10000)
                    await element.screenshot(path=filepath)
                else:
                    # 页面截图
                    await session.page.screenshot(path=filepath, full_page=full_page)

                # 获取文件大小
                file_size = os.path.getsize(filepath)

                return {
                    "success": True,
                    "session_id": session_id,
                    "screenshot_path": filepath,
                    "filename": filename,
                    "file_size_bytes": file_size,
                    "full_page": full_page,
                    "selector": selector or "(viewport)",
                    "message": f"截图已保存: {filepath} ({file_size} bytes)"
                }
            except Exception as e:
                logger.error(f"浏览器截图失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_get_network_log(
            session_id: str,
            filter_url: str = "",
            filter_type: str = ""
        ) -> Dict[str, Any]:
            """
            获取浏览器网络请求日志

            用于分析心跳请求、API调用模式、认证流程等。
            可以发现隐藏的API端点和认证token传递方式。

            Args:
                session_id: 会话ID
                filter_url: URL过滤（支持部分匹配）
                filter_type: 类型过滤 (xhr/fetch/websocket/document/script/stylesheet/image)

            Returns:
                网络请求日志列表
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 获取网络日志
                network_log = []
                if hasattr(session, "network_log"):
                    network_log = session.network_log
                elif hasattr(session, "get_network_log"):
                    network_log = session.get_network_log()

                # 过滤
                filtered = network_log
                if filter_url:
                    filtered = [req for req in filtered if filter_url in req.get("url", "")]
                if filter_type:
                    type_map = {
                        "xhr": "xmlhttprequest",
                        "fetch": "fetch",
                        "websocket": "websocket",
                        "document": "document",
                        "script": "script",
                        "stylesheet": "stylesheet",
                        "image": "image",
                    }
                    mapped_type = type_map.get(filter_type.lower(), filter_type.lower())
                    filtered = [req for req in filtered if req.get("resource_type", "").lower() == mapped_type]

                # 限制返回数量避免过大
                total_count = len(filtered)
                if len(filtered) > 500:
                    filtered = filtered[-500:]  # 保留最近500条

                return {
                    "success": True,
                    "session_id": session_id,
                    "total_requests": total_count,
                    "returned_requests": len(filtered),
                    "filter_url": filter_url or "(none)",
                    "filter_type": filter_type or "(none)",
                    "requests": filtered,
                    "message": f"网络日志: {total_count} 条请求 (返回 {len(filtered)} 条)"
                }
            except Exception as e:
                logger.error(f"获取网络日志失败: {e}")
                return {"success": False, "error": str(e)}

        # ==================== 4. 高级功能工具 (2个) ====================

        @mcp.tool()
        async def browser_heartbeat_status(
            session_id: str
        ) -> Dict[str, Any]:
            """
            查看当前会话的心跳检测状态

            分析目标网站使用的保活机制，包括：
            - WebSocket长连接心跳
            - XHR/Fetch轮询
            - EventSource (SSE)
            - 页面可见性API检测

            Args:
                session_id: 会话ID

            Returns:
                detected_heartbeats: 检测到的心跳列表
                websocket_connections: WebSocket连接状态
                xhr_polling: XHR轮询请求
                status: active/inactive
                uptime: 会话存活时间
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 获取心跳状态
                heartbeat_data = {
                    "detected_heartbeats": [],
                    "websocket_connections": [],
                    "xhr_polling": [],
                    "status": "unknown",
                    "uptime_seconds": 0,
                }

                if hasattr(session, "get_heartbeat_status"):
                    hb = session.get_heartbeat_status()
                    if isinstance(hb, dict):
                        heartbeat_data.update(hb)

                # 补充 WebSocket 连接信息 (通过JS检测)
                try:
                    ws_info = await session.page.evaluate("""() => {
                        // 检测页面中的WebSocket连接
                        const wsInfo = [];
                        if (window._ws_connections) {
                            window._ws_connections.forEach(ws => {
                                wsInfo.push({
                                    url: ws.url,
                                    readyState: ws.readyState,
                                    protocol: ws.protocol
                                });
                            });
                        }
                        return {
                            performance_entries: performance.getEntriesByType('resource')
                                .filter(e => e.initiatorType === 'xmlhttprequest' || e.initiatorType === 'fetch')
                                .slice(-20)
                                .map(e => ({
                                    name: e.name,
                                    type: e.initiatorType,
                                    duration: Math.round(e.duration),
                                    startTime: Math.round(e.startTime)
                                })),
                            ws_connections: wsInfo
                        };
                    }""")
                    if ws_info:
                        if ws_info.get("ws_connections"):
                            heartbeat_data["websocket_connections"] = ws_info["ws_connections"]
                        if ws_info.get("performance_entries"):
                            heartbeat_data["recent_xhr_fetch"] = ws_info["performance_entries"]
                except Exception:
                    pass

                # 计算 uptime
                if hasattr(session, "created_at") and session.created_at:
                    heartbeat_data["uptime_seconds"] = round(time.time() - session.created_at, 1)

                return {
                    "success": True,
                    "session_id": session_id,
                    **heartbeat_data,
                    "message": f"心跳状态: {heartbeat_data.get('status', 'unknown')}"
                }
            except Exception as e:
                logger.error(f"获取心跳状态失败: {e}")
                return {"success": False, "error": str(e)}

        @mcp.tool()
        async def browser_intercept_request(
            session_id: str,
            url_pattern: str,
            action: str = "log",
            modify_headers: str = "{}",
            modify_body: str = ""
        ) -> Dict[str, Any]:
            """
            拦截和修改浏览器请求 - 类Burp Proxy功能

            可以在浏览器级别拦截、记录或修改HTTP请求，
            无需额外配置代理。适用于修改API请求参数、
            注入自定义Header、替换请求体等场景。

            Args:
                session_id: 会话ID
                url_pattern: URL匹配模式（支持通配符 * ）
                action: log(仅记录) / block(阻断) / modify(修改)
                modify_headers: JSON格式的替换/追加头部（仅action=modify时生效）
                modify_body: 替换请求体（仅action=modify时生效）

            Returns:
                拦截规则设置结果
            """
            try:
                engine = await _get_engine()
                session = engine.get_session(session_id)

                if session is None:
                    return {"success": False, "error": f"会话不存在: {session_id}"}

                # 解析修改头部
                headers_to_modify = {}
                if modify_headers and modify_headers != "{}":
                    try:
                        headers_to_modify = json_module.loads(modify_headers)
                    except json_module.JSONDecodeError:
                        return {"success": False, "error": f"modify_headers JSON格式无效: {modify_headers}"}

                # 构建拦截处理函数
                import re as re_module
                # 将通配符模式转换为正则
                regex_pattern = url_pattern.replace("*", ".*").replace("?", ".")

                intercepted_requests = []

                async def route_handler(route):
                    request = route.request
                    req_info = {
                        "url": request.url,
                        "method": request.method,
                        "headers": dict(request.headers),
                        "post_data": request.post_data,
                        "resource_type": request.resource_type,
                        "timestamp": time.time(),
                    }

                    if action == "log":
                        intercepted_requests.append(req_info)
                        await route.continue_()

                    elif action == "block":
                        intercepted_requests.append({**req_info, "action": "blocked"})
                        await route.abort("blockedbyclient")

                    elif action == "modify":
                        overrides = {}
                        if headers_to_modify:
                            merged_headers = dict(request.headers)
                            merged_headers.update(headers_to_modify)
                            overrides["headers"] = merged_headers
                        if modify_body:
                            overrides["post_data"] = modify_body
                        intercepted_requests.append({**req_info, "action": "modified", "modifications": overrides})
                        await route.continue_(**overrides)

                    else:
                        await route.continue_()

                # 注册路由拦截
                await session.page.route(re_module.compile(regex_pattern), route_handler)

                # 将拦截记录绑定到会话以便后续查询
                if not hasattr(session, "_intercept_logs"):
                    session._intercept_logs = {}
                session._intercept_logs[url_pattern] = intercepted_requests

                return {
                    "success": True,
                    "session_id": session_id,
                    "url_pattern": url_pattern,
                    "regex_pattern": regex_pattern,
                    "action": action,
                    "modify_headers": headers_to_modify if headers_to_modify else None,
                    "modify_body": modify_body if modify_body else None,
                    "message": f"请求拦截规则已设置: {action} - {url_pattern}"
                }
            except Exception as e:
                logger.error(f"设置请求拦截失败: {e}")
                return {"success": False, "error": str(e)}

        logger.info(" 浏览器自动化 12 个MCP工具注册成功")

    except Exception as e:
        logger.warning(f" 浏览器自动化工具注册失败: {e}")
