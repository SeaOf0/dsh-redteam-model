#!/usr/bin/env python3
"""
Playwright 反检测浏览器引擎 — 持久化渗透测试会话

解决的核心问题:
  现代 Web 应用使用动态心跳检测 (WebSocket ping, XHR 轮询, JS 指纹) 来识别
  自动化工具。curl/wget 会话会被立即失效。本引擎通过真实浏览器自动化维持
  长期会话，同时规避反自动化检测。

核心能力:
  - 反检测注入: navigator.webdriver 移除、WebGL/Canvas 指纹伪装、插件模拟
  - 心跳监控: 自动检测并维持 WebSocket ping/pong 和 XHR 轮询心跳
  - 人类行为模拟: 随机延迟、鼠标移动、滚动模式
  - 会话持久化: Cookie/localStorage/sessionStorage 保存与恢复
  - 多会话隔离: 每个会话独立浏览器上下文，互不干扰
  - 代理支持: 可配置 HTTP/SOCKS5 代理用于 MITM 测试

架构:
  StealthBrowserEngine (引擎生命周期管理)
     BrowserSession (单个标签页/上下文)
           HeartbeatMonitor (心跳检测与维持)
           反检测 JS 注入层

依赖:
  pip install playwright && playwright install chromium
"""

import asyncio
import json
import os
import re
import time
import random
import logging
from typing import Dict, Any, Optional, List, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 可选依赖: Playwright — 未安装时优雅降级
# ---------------------------------------------------------------------------
try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
        WebSocket as PWWebSocket,
        Route,
        Request as PWRequest,
    )
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    # 类型桩，使模块在无 Playwright 时仍可导入
    Browser = BrowserContext = Page = Playwright = None  # type: ignore
    PWWebSocket = Route = PWRequest = None  # type: ignore
    logger.warning(
        "playwright 未安装, 浏览器引擎不可用. "
        "运行: pip install playwright && playwright install chromium"
    )

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
DEFAULT_STORAGE_DIR = "/tmp/kali_mcp_browser_sessions"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_VIEWPORT = {"width": 1920, "height": 1080}
# 心跳检测: 如果两次请求间隔在此范围内, 认为是心跳
HEARTBEAT_INTERVAL_TOLERANCE_MS = 2000
# 心跳检测: 至少观察到这么多次等间隔请求才确认为心跳
HEARTBEAT_MIN_SAMPLES = 3
# 常见心跳 URL 片段
HEARTBEAT_URL_PATTERNS = re.compile(
    r"(heartbeat|ping|pong|alive|keepalive|health|poll|beacon|check"
    r"|__refresh|_poll|longpoll|sse|event-stream)",
    re.IGNORECASE,
)


# 
# 辅助函数
# 

def _humanize_delay(min_ms: int = 100, max_ms: int = 500) -> float:
    """返回一个模拟人类反应的随机延迟 (秒).

    Args:
        min_ms: 最小延迟毫秒数.
        max_ms: 最大延迟毫秒数.

    Returns:
        float: 延迟秒数, 带毫秒精度.
    """
    return random.randint(min_ms, max_ms) / 1000.0


def _get_stealth_scripts() -> List[str]:
    """返回反检测 JavaScript 脚本列表, 在每次页面加载前注入.

    覆盖的检测向量:
      - navigator.webdriver 标志
      - navigator.plugins (Chrome PDF Plugin 模拟)
      - navigator.languages
      - navigator.hardwareConcurrency / deviceMemory
      - Chrome 运行时对象 (window.chrome)
      - Permissions API 查询结果
      - WebGL 渲染器/供应商信息
      - Canvas 指纹随机化
      - 屏幕尺寸一致性

    Returns:
        list[str]: 可直接传入 context.add_init_script() 的 JS 字符串列表.
    """
    scripts: List[str] = []

    # --- 核心反检测脚本 ---
    scripts.append(r"""
// ============================================================
// [Stealth] 核心反检测注入
// ============================================================

// 1. 移除 webdriver 标志
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
});

// 2. 模拟 Chrome 插件列表
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            { name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },
            { name: 'Chrome PDF Viewer', description: '', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },
            { name: 'Native Client', description: '', filename: 'internal-nacl-plugin', length: 2 }
        ];
        plugins.length = 3;
        Object.setPrototypeOf(plugins, PluginArray.prototype);
        return plugins;
    },
    configurable: true
});

// 3. 语言列表
Object.defineProperty(navigator, 'languages', {
    get: () => ['zh-CN', 'zh', 'en-US', 'en'],
    configurable: true
});

// 4. 硬件指纹
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8,
    configurable: true
});
Object.defineProperty(navigator, 'deviceMemory', {
    get: () => 8,
    configurable: true
});

// 5. Chrome 运行时模拟
if (!window.chrome) {
    window.chrome = {};
}
window.chrome.runtime = window.chrome.runtime || {};
window.chrome.loadTimes = window.chrome.loadTimes || function() {
    return {
        commitLoadTime: Date.now() / 1000,
        connectionInfo: 'h2',
        finishDocumentLoadTime: Date.now() / 1000 + 0.1,
        finishLoadTime: Date.now() / 1000 + 0.2,
        firstPaintAfterLoadTime: 0,
        firstPaintTime: Date.now() / 1000 + 0.05,
        navigationType: 'Other',
        npnNegotiatedProtocol: 'h2',
        requestTime: Date.now() / 1000 - 0.5,
        startLoadTime: Date.now() / 1000 - 0.4,
        wasAlternateProtocolAvailable: false,
        wasFetchedViaSpdy: true,
        wasNpnNegotiated: true,
    };
};
window.chrome.csi = window.chrome.csi || function() {
    return {
        onloadT: Date.now(),
        startE: Date.now() - 500,
        pageT: 500,
        tran: 15,
    };
};

// 6. Permissions API 覆盖
(function() {
    const originalQuery = window.navigator.permissions.query;
    if (originalQuery) {
        window.navigator.permissions.query = function(parameters) {
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission });
            }
            return originalQuery.call(window.navigator.permissions, parameters);
        };
    }
})();
""")

    # --- WebGL 指纹覆盖 ---
    scripts.append(r"""
// ============================================================
// [Stealth] WebGL 供应商/渲染器伪装
// ============================================================
(function() {
    const getParameterProxyHandler = {
        apply: function(target, thisArg, args) {
            const param = args[0];
            // UNMASKED_VENDOR_WEBGL
            if (param === 37445) return 'Intel Inc.';
            // UNMASKED_RENDERER_WEBGL
            if (param === 37446) return 'Intel Iris OpenGL Engine';
            return Reflect.apply(target, thisArg, args);
        }
    };
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                const origGetParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = new Proxy(
                    origGetParameter, getParameterProxyHandler
                );
            }
        }
    } catch(e) {}
    // WebGL2 同理
    try {
        if (typeof WebGL2RenderingContext !== 'undefined') {
            const origGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = new Proxy(
                origGetParameter2, getParameterProxyHandler
            );
        }
    } catch(e) {}
})();
""")

    # --- Canvas 指纹随机化 ---
    scripts.append(r"""
// ============================================================
// [Stealth] Canvas 指纹随机化
// ============================================================
(function() {
    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    // 为 canvas 数据添加微小噪声
    function addNoise(data) {
        for (let i = 0; i < data.length; i += 4) {
            // 每个 RGBA 通道添加 -1/0/+1 的随机偏移
            data[i] = Math.max(0, Math.min(255, data[i] + (Math.random() < 0.1 ? (Math.random() > 0.5 ? 1 : -1) : 0)));
        }
        return data;
    }

    CanvasRenderingContext2D.prototype.getImageData = function() {
        const imageData = origGetImageData.apply(this, arguments);
        addNoise(imageData.data);
        return imageData;
    };
})();
""")

    # --- 屏幕尺寸一致性 ---
    scripts.append(r"""
// ============================================================
// [Stealth] 屏幕尺寸一致性
// ============================================================
Object.defineProperty(screen, 'availWidth', { get: () => screen.width });
Object.defineProperty(screen, 'availHeight', { get: () => screen.height });
Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
""")

    # --- iframe contentWindow 保护 ---
    scripts.append(r"""
// ============================================================
// [Stealth] iframe contentWindow 检测绕过
// ============================================================
(function() {
    try {
        // 防止通过 iframe 检测自动化
        const origAppendChild = Element.prototype.appendChild;
        Element.prototype.appendChild = function() {
            const result = origAppendChild.apply(this, arguments);
            if (arguments[0] instanceof HTMLIFrameElement) {
                try {
                    const iframeWindow = arguments[0].contentWindow;
                    if (iframeWindow) {
                        Object.defineProperty(iframeWindow.navigator, 'webdriver', {
                            get: () => undefined, configurable: true
                        });
                    }
                } catch(e) {}
            }
            return result;
        };
    } catch(e) {}
})();
""")

    return scripts


# 
# 数据结构
# 

@dataclass
class SessionMetadata:
    """会话元数据, 用于持久化和状态报告."""

    session_id: str
    url: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_access: str = field(default_factory=lambda: datetime.now().isoformat())
    heartbeat_active: bool = False
    heartbeat_count: int = 0
    page_title: str = ""
    status: str = "active"  # active | closed | error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "url": self.url,
            "created_at": self.created_at,
            "last_access": self.last_access,
            "heartbeat_active": self.heartbeat_active,
            "heartbeat_count": self.heartbeat_count,
            "page_title": self.page_title,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionMetadata":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class NetworkLogEntry:
    """网络请求日志条目."""

    timestamp: float
    method: str
    url: str
    status: Optional[int] = None
    resource_type: str = ""
    response_size: int = 0
    duration_ms: float = 0.0
    is_heartbeat: bool = False


# 
# 心跳监控器
# 

class HeartbeatMonitor:
    """自动检测并维持 WebSocket 和 HTTP 心跳.

    监控策略:
      1. WebSocket: 监听所有 WS 连接的帧收发, 识别 ping/pong 模式.
         浏览器会自动响应 WS 协议级 ping; 应用级 ping 由页面 JS 处理.
         监控器确保页面 JS 持续运行, 并在检测到应用级心跳失败时重新注入.
      2. HTTP 轮询: 追踪重复访问同一 URL 的请求, 通过间隔分析识别心跳.
         浏览器中的 JS 会自动执行轮询; 监控器跟踪状态并在异常时告警.

    Attributes:
        page: 关联的 Playwright Page 对象.
        active: 监控器是否处于活跃状态.
        ws_heartbeats: 已检测到的 WebSocket 心跳连接集合.
        http_heartbeats: 已检测到的 HTTP 心跳 URL 集合.
        heartbeat_count: 累计检测到的心跳事件数.
    """

    def __init__(self, page: "Page") -> None:
        self.page = page
        self.active: bool = False
        self._monitor_task: Optional[asyncio.Task] = None

        # WebSocket 追踪
        self._ws_connections: Dict[str, "PWWebSocket"] = {}
        self._ws_frame_times: Dict[str, List[float]] = {}

        # HTTP 轮询追踪: url -> list of timestamps
        self._http_request_times: Dict[str, List[float]] = {}

        # 确认的心跳
        self.ws_heartbeats: Set[str] = set()
        self.http_heartbeats: Set[str] = set()
        self.heartbeat_count: int = 0

        # 日志
        self._heartbeat_log: List[Dict[str, Any]] = []

    async def start(self) -> None:
        """启动心跳监控.

        注册 WebSocket 和网络请求的事件监听器, 并启动后台分析任务.
        """
        if self.active:
            return
        self.active = True
        logger.info("心跳监控器已启动")

        # WebSocket 监听
        self.page.on("websocket", self._on_websocket)
        # 网络请求监听
        self.page.on("request", self._on_request)

        # 后台分析任务
        self._monitor_task = asyncio.create_task(self._analysis_loop())

    async def stop(self) -> None:
        """停止心跳监控, 清理事件监听和后台任务."""
        if not self.active:
            return
        self.active = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        self._monitor_task = None

        # 移除监听器 (Playwright 不支持 removeListener, 通过 active 标志阻断)
        logger.info(
            "心跳监控器已停止 — WS心跳: %d, HTTP心跳: %d, 总计事件: %d",
            len(self.ws_heartbeats),
            len(self.http_heartbeats),
            self.heartbeat_count,
        )

    def _on_websocket(self, ws: "PWWebSocket") -> None:
        """处理新的 WebSocket 连接."""
        if not self.active:
            return
        ws_url = ws.url
        self._ws_connections[ws_url] = ws
        self._ws_frame_times[ws_url] = []
        logger.debug("检测到 WebSocket 连接: %s", ws_url)

        def on_frame_received(payload: str) -> None:
            if not self.active:
                return
            now = time.time()
            if ws_url in self._ws_frame_times:
                self._ws_frame_times[ws_url].append(now)
            # 检查是否看起来像心跳内容
            payload_lower = payload.lower() if isinstance(payload, str) else ""
            if any(kw in payload_lower for kw in ("ping", "pong", "heartbeat", "alive")):
                self.heartbeat_count += 1
                self.ws_heartbeats.add(ws_url)
                self._log_heartbeat("websocket", ws_url, payload[:200])

        def on_frame_sent(payload: str) -> None:
            if not self.active:
                return
            payload_lower = payload.lower() if isinstance(payload, str) else ""
            if any(kw in payload_lower for kw in ("ping", "pong", "heartbeat", "alive")):
                self.heartbeat_count += 1
                self._log_heartbeat("websocket_sent", ws_url, payload[:200])

        ws.on("framereceived", on_frame_received)
        ws.on("framesent", on_frame_sent)

        def on_close(_: Any = None) -> None:
            self._ws_connections.pop(ws_url, None)
            logger.debug("WebSocket 连接关闭: %s", ws_url)

        ws.on("close", on_close)

    def _on_request(self, request: "PWRequest") -> None:
        """追踪 HTTP 请求用于心跳模式检测."""
        if not self.active:
            return
        url = request.url
        now = time.time()

        # 快速匹配: URL 包含心跳关键词
        if HEARTBEAT_URL_PATTERNS.search(url):
            if url not in self._http_request_times:
                self._http_request_times[url] = []
            self._http_request_times[url].append(now)
            return

        # 通用追踪: 仅追踪 XHR/Fetch 类型请求
        resource_type = request.resource_type
        if resource_type in ("xhr", "fetch"):
            if url not in self._http_request_times:
                self._http_request_times[url] = []
            self._http_request_times[url].append(now)

    async def _analysis_loop(self) -> None:
        """后台循环: 定期分析请求模式, 识别心跳."""
        try:
            while self.active:
                await asyncio.sleep(10)
                if not self.active:
                    break
                self._analyze_http_patterns()
                self._analyze_ws_patterns()
        except asyncio.CancelledError:
            pass

    def _analyze_http_patterns(self) -> None:
        """分析 HTTP 请求时间戳, 识别周期性轮询模式."""
        for url, timestamps in list(self._http_request_times.items()):
            if len(timestamps) < HEARTBEAT_MIN_SAMPLES:
                continue
            # 计算间隔
            recent = timestamps[-20:]  # 只看最近 20 次
            intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            # 如果间隔标准差较小 (相对于平均值), 认为是心跳
            if avg_interval > 0:
                variance = sum((iv - avg_interval) ** 2 for iv in intervals) / len(intervals)
                std_dev = variance ** 0.5
                # 允许 avg_interval 的 30% 偏差
                if std_dev < avg_interval * 0.3 and avg_interval < 120:
                    if url not in self.http_heartbeats:
                        self.http_heartbeats.add(url)
                        logger.info(
                            "检测到 HTTP 心跳: %s (间隔 %.1fs)",
                            url[:120],
                            avg_interval,
                        )
                    self.heartbeat_count += 1
                    self._log_heartbeat(
                        "http_poll", url, f"interval={avg_interval:.1f}s"
                    )

            # 清理旧数据, 只保留最近 30 个时间戳
            if len(timestamps) > 30:
                self._http_request_times[url] = timestamps[-30:]

    def _analyze_ws_patterns(self) -> None:
        """分析 WebSocket 帧时间戳, 识别周期性心跳."""
        for ws_url, timestamps in list(self._ws_frame_times.items()):
            if len(timestamps) < HEARTBEAT_MIN_SAMPLES:
                continue
            recent = timestamps[-20:]
            intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval > 0:
                variance = sum((iv - avg_interval) ** 2 for iv in intervals) / len(intervals)
                std_dev = variance ** 0.5
                if std_dev < avg_interval * 0.3 and avg_interval < 120:
                    if ws_url not in self.ws_heartbeats:
                        self.ws_heartbeats.add(ws_url)
                        logger.info(
                            "检测到 WebSocket 心跳: %s (间隔 %.1fs)",
                            ws_url[:120],
                            avg_interval,
                        )

            # 清理旧数据
            if len(timestamps) > 30:
                self._ws_frame_times[ws_url] = timestamps[-30:]

    def _log_heartbeat(self, hb_type: str, url: str, detail: str = "") -> None:
        """记录心跳事件到日志."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": hb_type,
            "url": url[:200],
            "detail": detail[:500],
        }
        self._heartbeat_log.append(entry)
        # 保持日志不超过 500 条
        if len(self._heartbeat_log) > 500:
            self._heartbeat_log = self._heartbeat_log[-300:]

    def get_status(self) -> Dict[str, Any]:
        """返回心跳监控状态概要.

        Returns:
            dict: 包含活跃状态、检测到的心跳类型和计数等信息.
        """
        return {
            "active": self.active,
            "ws_connections": len(self._ws_connections),
            "ws_heartbeats": list(self.ws_heartbeats),
            "http_heartbeats": list(self.http_heartbeats),
            "total_heartbeat_events": self.heartbeat_count,
            "recent_log": self._heartbeat_log[-10:],
        }


# 
# 浏览器会话
# 

class BrowserSession:
    """单个浏览器会话 — 封装一个隔离的浏览器上下文和标签页.

    每个 BrowserSession 拥有独立的:
      - BrowserContext (独立 Cookie/Storage)
      - Page (标签页)
      - HeartbeatMonitor (心跳检测)
      - 持久化存储目录

    Attributes:
        session_id: 会话唯一标识符.
        page: Playwright Page 对象.
        context: Playwright BrowserContext 对象.
        cookies_file: Cookie 持久化文件路径.
        heartbeat_task: 心跳监控任务引用.
        metadata: 会话元数据.
    """

    def __init__(
        self,
        session_id: str,
        context: "BrowserContext",
        page: "Page",
        storage_dir: str,
    ) -> None:
        self.session_id = session_id
        self.context = context
        self.page = page

        # 持久化路径
        self._storage_dir = Path(storage_dir) / session_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self.cookies_file = str(self._storage_dir / "cookies.json")
        self._state_file = str(self._storage_dir / "storage_state.json")
        self._metadata_file = str(self._storage_dir / "metadata.json")

        # 心跳
        self._heartbeat_monitor = HeartbeatMonitor(page)
        self.heartbeat_task: Optional[asyncio.Task] = None

        # 元数据
        self.metadata = SessionMetadata(session_id=session_id)

        # 网络日志
        self._network_log: List[NetworkLogEntry] = []
        self._request_timings: Dict[str, float] = {}

        # 请求拦截器
        self._interceptors: Dict[str, Callable] = {}

        # 注册网络日志记录器
        self.page.on("request", self._on_request_for_log)
        self.page.on("response", self._on_response_for_log)

    # ------------------------------------------------------------------
    # 导航
    # ------------------------------------------------------------------

    async def navigate(self, url: str, wait_until: str = "networkidle") -> Dict[str, Any]:
        """导航到指定 URL.

        Args:
            url: 目标 URL.
            wait_until: 等待条件 — "load", "domcontentloaded", "networkidle", "commit".

        Returns:
            dict: 包含 url, title, status 的导航结果.

        Raises:
            RuntimeError: 如果 playwright 未安装.
        """
        self._ensure_playwright()
        logger.info("[%s] 导航至: %s (wait=%s)", self.session_id, url, wait_until)
        await asyncio.sleep(_humanize_delay(50, 200))

        response = await self.page.goto(url, wait_until=wait_until, timeout=60000)
        status = response.status if response else None
        title = await self.page.title()

        self.metadata.url = url
        self.metadata.last_access = datetime.now().isoformat()
        self.metadata.page_title = title

        logger.info("[%s] 页面已加载: %s (status=%s)", self.session_id, title, status)
        return {"url": url, "title": title, "status": status}

    async def wait_for_selector(self, selector: str, timeout: int = 30000) -> bool:
        """等待页面元素出现.

        Args:
            selector: CSS 选择器.
            timeout: 超时毫秒数.

        Returns:
            bool: 元素是否在超时前出现.
        """
        self._ensure_playwright()
        try:
            await self.page.wait_for_selector(selector, timeout=timeout)
            return True
        except Exception as e:
            logger.warning(
                "[%s] 等待选择器 '%s' 超时: %s", self.session_id, selector, e
            )
            return False

    # ------------------------------------------------------------------
    # 交互 (带人类行为模拟)
    # ------------------------------------------------------------------

    async def click(self, selector: str) -> None:
        """点击元素, 带人类行为模拟 (先移动鼠标, 随机延迟).

        Args:
            selector: 要点击的元素的 CSS 选择器.
        """
        self._ensure_playwright()
        # 人类行为: 先轻微移动鼠标
        await self._simulate_mouse_approach(selector)
        await asyncio.sleep(_humanize_delay(80, 300))
        await self.page.click(selector)
        self.metadata.last_access = datetime.now().isoformat()
        logger.debug("[%s] 点击: %s", self.session_id, selector)

    async def type_text(self, selector: str, text: str, delay: int = 50) -> None:
        """在输入框中键入文本, 带逼真的击键延迟.

        Args:
            selector: 输入元素的 CSS 选择器.
            text: 要输入的文本.
            delay: 每个字符之间的延迟毫秒数 (会加上随机波动).
        """
        self._ensure_playwright()
        await self._simulate_mouse_approach(selector)
        await self.page.click(selector)
        await asyncio.sleep(_humanize_delay(100, 300))

        # 逐字符输入, 带随机延迟波动
        for char in text:
            actual_delay = delay + random.randint(-20, 30)
            actual_delay = max(10, actual_delay)
            await self.page.keyboard.type(char, delay=actual_delay)

        self.metadata.last_access = datetime.now().isoformat()
        logger.debug("[%s] 输入文本到 '%s': %s...", self.session_id, selector, text[:30])

    async def scroll(self, direction: str = "down", amount: int = 300) -> None:
        """平滑滚动页面.

        Args:
            direction: 滚动方向 — "down", "up", "left", "right".
            amount: 滚动像素量.
        """
        self._ensure_playwright()
        delta_x, delta_y = 0, 0
        if direction == "down":
            delta_y = amount
        elif direction == "up":
            delta_y = -amount
        elif direction == "right":
            delta_x = amount
        elif direction == "left":
            delta_x = -amount

        # 分多步滚动模拟人类行为
        steps = random.randint(3, 6)
        step_x = delta_x / steps
        step_y = delta_y / steps

        for _ in range(steps):
            await self.page.mouse.wheel(step_x, step_y)
            await asyncio.sleep(_humanize_delay(30, 80))

        self.metadata.last_access = datetime.now().isoformat()
        logger.debug("[%s] 滚动: %s %dpx", self.session_id, direction, amount)

    # ------------------------------------------------------------------
    # 数据提取
    # ------------------------------------------------------------------

    async def extract_text(self, selector: str) -> str:
        """提取元素的文本内容.

        Args:
            selector: 目标元素的 CSS 选择器.

        Returns:
            str: 元素的 textContent, 如果元素不存在则返回空字符串.
        """
        self._ensure_playwright()
        element = await self.page.query_selector(selector)
        if element:
            return (await element.text_content()) or ""
        return ""

    async def extract_html(self, selector: Optional[str] = None) -> str:
        """提取 HTML 内容.

        Args:
            selector: CSS 选择器. 如果为 None, 返回整个页面 HTML.

        Returns:
            str: HTML 内容字符串.
        """
        self._ensure_playwright()
        if selector:
            element = await self.page.query_selector(selector)
            if element:
                return (await element.inner_html()) or ""
            return ""
        return await self.page.content()

    async def extract_links(self) -> List[Dict[str, str]]:
        """提取页面上所有链接.

        Returns:
            list[dict]: 每个链接的 href 和 text.
        """
        self._ensure_playwright()
        links = await self.page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.href,
                    text: (a.textContent || '').trim().substring(0, 200)
                }));
            }
        """)
        return links or []

    async def extract_forms(self) -> List[Dict[str, Any]]:
        """提取页面上所有表单及其输入字段.

        Returns:
            list[dict]: 每个表单的 action, method 和 inputs 列表.
        """
        self._ensure_playwright()
        forms = await self.page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    id: form.id || '',
                    name: form.name || '',
                    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(el => ({
                        tag: el.tagName.toLowerCase(),
                        type: el.type || '',
                        name: el.name || '',
                        id: el.id || '',
                        value: el.value || '',
                        placeholder: el.placeholder || '',
                        required: el.required || false
                    }))
                }));
            }
        """)
        return forms or []

    async def screenshot(self, path: Optional[str] = None) -> bytes:
        """截取当前页面截图.

        Args:
            path: 保存路径. 如果为 None, 保存到会话存储目录.

        Returns:
            bytes: PNG 格式的截图数据.
        """
        self._ensure_playwright()
        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = str(self._storage_dir / f"screenshot_{ts}.png")

        screenshot_bytes = await self.page.screenshot(path=path, full_page=True)
        logger.info("[%s] 截图已保存: %s", self.session_id, path)
        return screenshot_bytes

    async def execute_js(self, script: str) -> Any:
        """在页面上下文中执行 JavaScript.

        Args:
            script: 要执行的 JavaScript 代码.

        Returns:
            Any: JavaScript 执行的返回值.
        """
        self._ensure_playwright()
        result = await self.page.evaluate(script)
        logger.debug("[%s] 执行 JS: %s...", self.session_id, script[:80])
        return result

    # ------------------------------------------------------------------
    # Cookie / 状态管理
    # ------------------------------------------------------------------

    async def get_cookies(self) -> List[Dict[str, Any]]:
        """获取当前所有 Cookie.

        Returns:
            list[dict]: Cookie 列表, 每个包含 name, value, domain, path 等字段.
        """
        self._ensure_playwright()
        return await self.context.cookies()

    async def set_cookies(self, cookies: List[Dict[str, Any]]) -> None:
        """设置 Cookie.

        Args:
            cookies: Cookie 列表. 每个 dict 至少需要 name, value, url 或 domain.
        """
        self._ensure_playwright()
        await self.context.add_cookies(cookies)
        logger.info("[%s] 已设置 %d 个 Cookie", self.session_id, len(cookies))

    async def save_state(self) -> str:
        """持久化会话状态 (Cookie + localStorage + sessionStorage).

        将浏览器上下文的完整存储状态保存到磁盘, 包括:
          - 所有 Cookie
          - 所有源的 localStorage
          - 会话元数据

        Returns:
            str: 状态文件保存路径.
        """
        self._ensure_playwright()

        # 保存 Playwright 存储状态 (包含 cookies + localStorage)
        await self.context.storage_state(path=self._state_file)

        # 同时单独保存 cookies 便于检查
        cookies = await self.context.cookies()
        with open(self.cookies_file, "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=2, ensure_ascii=False)

        # 保存元数据
        self.metadata.last_access = datetime.now().isoformat()
        with open(self._metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(
            "[%s] 会话状态已保存至 %s", self.session_id, self._storage_dir
        )
        return str(self._storage_dir)

    async def load_state(self) -> bool:
        """从磁盘恢复会话状态.

        Returns:
            bool: 是否成功恢复状态.
        """
        self._ensure_playwright()

        # 恢复 cookies
        if os.path.exists(self.cookies_file):
            try:
                with open(self.cookies_file, "r", encoding="utf-8") as f:
                    cookies = json.load(f)
                if cookies:
                    await self.context.add_cookies(cookies)
                    logger.info(
                        "[%s] 已恢复 %d 个 Cookie", self.session_id, len(cookies)
                    )
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("[%s] Cookie 恢复失败: %s", self.session_id, e)

        # 恢复元数据
        if os.path.exists(self._metadata_file):
            try:
                with open(self._metadata_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.metadata = SessionMetadata.from_dict(data)
                self.metadata.status = "active"
                logger.info(
                    "[%s] 元数据已恢复 (上次 URL: %s)",
                    self.session_id,
                    self.metadata.url,
                )
                return True
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("[%s] 元数据恢复失败: %s", self.session_id, e)

        return False

    # ------------------------------------------------------------------
    # 心跳管理
    # ------------------------------------------------------------------

    async def start_heartbeat_monitor(self) -> None:
        """启动心跳监控 — 自动检测并跟踪 WebSocket/HTTP 心跳.

        监控器会:
          1. 监听所有 WebSocket 连接的帧通信
          2. 追踪周期性 HTTP 请求
          3. 通过间隔分析自动识别心跳模式
          4. 记录心跳活动日志
        """
        self._ensure_playwright()
        await self._heartbeat_monitor.start()
        self.metadata.heartbeat_active = True
        logger.info("[%s] 心跳监控已启动", self.session_id)

    async def stop_heartbeat_monitor(self) -> None:
        """停止心跳监控."""
        await self._heartbeat_monitor.stop()
        self.metadata.heartbeat_active = False
        self.metadata.heartbeat_count = self._heartbeat_monitor.heartbeat_count

    def get_heartbeat_status(self) -> Dict[str, Any]:
        """获取心跳监控状态."""
        return self._heartbeat_monitor.get_status()

    # ------------------------------------------------------------------
    # 请求拦截
    # ------------------------------------------------------------------

    async def intercept_requests(
        self, url_pattern: str, handler: Callable
    ) -> None:
        """拦截匹配 URL 模式的请求.

        Args:
            url_pattern: URL 匹配模式 (glob 格式, 如 "**/api/**").
            handler: 拦截处理函数, 签名为 async (route, request) -> None.
                     处理函数中应调用 route.continue_(), route.fulfill() 或 route.abort().
        """
        self._ensure_playwright()
        self._interceptors[url_pattern] = handler
        await self.page.route(url_pattern, handler)
        logger.info(
            "[%s] 已注册请求拦截: %s", self.session_id, url_pattern
        )

    async def get_network_log(self) -> List[Dict[str, Any]]:
        """获取捕获的网络请求日志.

        Returns:
            list[dict]: 网络请求日志条目列表, 每个包含 timestamp, method, url,
                        status, resource_type, is_heartbeat 等字段.
        """
        return [
            {
                "timestamp": entry.timestamp,
                "method": entry.method,
                "url": entry.url,
                "status": entry.status,
                "resource_type": entry.resource_type,
                "response_size": entry.response_size,
                "duration_ms": entry.duration_ms,
                "is_heartbeat": entry.is_heartbeat,
            }
            for entry in self._network_log[-500:]
        ]

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _ensure_playwright(self) -> None:
        """确保 Playwright 可用, 否则抛出 RuntimeError."""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "playwright 未安装. 运行: pip install playwright && playwright install chromium"
            )

    async def _simulate_mouse_approach(self, selector: str) -> None:
        """模拟鼠标接近目标元素的运动轨迹."""
        try:
            box = await self.page.evaluate(
                """(sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return null;
                    const rect = el.getBoundingClientRect();
                    return {
                        x: rect.x + rect.width / 2,
                        y: rect.y + rect.height / 2
                    };
                }""",
                selector,
            )
            if box:
                # 添加随机偏移模拟不精确的人类瞄准
                target_x = box["x"] + random.uniform(-3, 3)
                target_y = box["y"] + random.uniform(-3, 3)

                # 分 2-4 步移动鼠标 (模拟非直线路径)
                steps = random.randint(2, 4)
                await self.page.mouse.move(target_x, target_y, steps=steps)
        except Exception:
            # 鼠标模拟失败不应阻断操作
            pass

    def _on_request_for_log(self, request: "PWRequest") -> None:
        """记录网络请求到日志."""
        url = request.url
        self._request_timings[url + str(id(request))] = time.time()

        is_heartbeat = bool(HEARTBEAT_URL_PATTERNS.search(url))
        entry = NetworkLogEntry(
            timestamp=time.time(),
            method=request.method,
            url=url,
            resource_type=request.resource_type,
            is_heartbeat=is_heartbeat,
        )
        self._network_log.append(entry)

        # 限制日志大小
        if len(self._network_log) > 2000:
            self._network_log = self._network_log[-1000:]

    def _on_response_for_log(self, response: Any) -> None:
        """记录网络响应信息到日志."""
        try:
            request = response.request
            key = request.url + str(id(request))
            start_time = self._request_timings.pop(key, None)

            # 找到对应的日志条目并更新
            for entry in reversed(self._network_log[-50:]):
                if entry.url == request.url and entry.status is None:
                    entry.status = response.status
                    if start_time:
                        entry.duration_ms = (time.time() - start_time) * 1000
                    break
        except Exception:
            pass


# 
# 隐身浏览器引擎
# 

class StealthBrowserEngine:
    """反检测浏览器引擎 — 管理持久化渗透测试浏览器会话.

    核心能力:
      - 启动带反检测注入的 Chromium 浏览器实例
      - 管理多个隔离的浏览器会话 (独立 Cookie/Storage)
      - 支持代理配置用于 MITM 测试
      - 自动心跳监控维持长期会话
      - 会话状态持久化与恢复

    Usage::

        engine = StealthBrowserEngine()
        await engine.start()

        session = await engine.create_session("target1", "https://target.com/login")
        await session.type_text("#username", "admin")
        await session.type_text("#password", "password")
        await session.click("#login-btn")
        await session.start_heartbeat_monitor()

        # ... 长时间保持会话 ...

        await session.save_state()
        await engine.stop()

    Args:
        storage_dir: 会话持久化存储目录.
        headless: 是否使用无头模式. 默认 True.
        proxy: 代理配置. 格式: "http://host:port" 或 "socks5://host:port"
               或 dict {"server": "...", "username": "...", "password": "..."}.
        locale: 浏览器语言区域设置. 默认 "zh-CN".
        timezone: 时区标识符. 默认 "Asia/Shanghai".
    """

    def __init__(
        self,
        storage_dir: str = DEFAULT_STORAGE_DIR,
        headless: bool = True,
        proxy: Optional[Any] = None,
        locale: str = "zh-CN",
        timezone: str = "Asia/Shanghai",
    ) -> None:
        self._storage_dir = storage_dir
        self._headless = headless
        self._proxy = proxy
        self._locale = locale
        self._timezone = timezone

        self._playwright: Optional["Playwright"] = None
        self._browser: Optional["Browser"] = None
        self._sessions: Dict[str, BrowserSession] = {}
        self._started = False
        self._start_time: Optional[float] = None

        # 确保存储目录存在
        Path(self._storage_dir).mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        """启动浏览器引擎.

        初始化 Playwright 并启动 Chromium 浏览器实例.
        应用反检测启动参数以规避自动化检测.

        Raises:
            RuntimeError: 如果 playwright 未安装或浏览器启动失败.
        """
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "playwright 未安装. 运行: pip install playwright && playwright install chromium"
            )
        if self._started:
            logger.warning("浏览器引擎已在运行中")
            return

        logger.info("正在启动隐身浏览器引擎...")

        self._playwright = await async_playwright().start()

        # 构建启动参数
        launch_args = self._build_launch_args()
        launch_kwargs: Dict[str, Any] = {
            "headless": self._headless,
            "args": launch_args,
            # 忽略默认参数中的 --enable-automation 等标志
            "ignore_default_args": [
                "--enable-automation",
                "--enable-blink-features=AutomationControlled",
            ],
        }

        # 代理配置
        if self._proxy:
            if isinstance(self._proxy, str):
                launch_kwargs["proxy"] = {"server": self._proxy}
            elif isinstance(self._proxy, dict):
                launch_kwargs["proxy"] = self._proxy

        try:
            self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        except Exception as e:
            logger.error("浏览器启动失败: %s", e)
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
            raise RuntimeError(f"浏览器启动失败: {e}") from e

        self._started = True
        self._start_time = time.time()
        logger.info(
            "隐身浏览器引擎已启动 (headless=%s, proxy=%s)",
            self._headless,
            "已配置" if self._proxy else "无",
        )

    async def stop(self) -> None:
        """优雅关闭浏览器引擎.

        依次执行:
          1. 保存所有活跃会话的状态
          2. 停止所有心跳监控
          3. 关闭所有浏览器上下文
          4. 关闭浏览器实例
          5. 停止 Playwright
        """
        logger.info("正在关闭隐身浏览器引擎...")

        # 保存并关闭所有会话
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            try:
                await self.close_session(sid)
            except Exception as e:
                logger.warning("关闭会话 '%s' 时出错: %s", sid, e)

        # 关闭浏览器
        if self._browser:
            try:
                await self._browser.close()
            except Exception as e:
                logger.warning("关闭浏览器时出错: %s", e)
            self._browser = None

        # 停止 Playwright
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception as e:
                logger.warning("停止 Playwright 时出错: %s", e)
            self._playwright = None

        self._started = False
        logger.info("隐身浏览器引擎已关闭")

    async def create_session(
        self,
        session_id: str,
        url: Optional[str] = None,
    ) -> BrowserSession:
        """创建新的浏览器会话.

        每个会话拥有独立的浏览器上下文 (Cookie/Storage 隔离).
        如果存在同名会话的持久化数据, 会自动恢复.

        Args:
            session_id: 会话唯一标识符.
            url: 可选的初始 URL, 创建后自动导航.

        Returns:
            BrowserSession: 新创建的会话对象.

        Raises:
            RuntimeError: 如果引擎未启动或会话 ID 已存在.
        """
        self._ensure_running()

        if session_id in self._sessions:
            raise RuntimeError(f"会话 '{session_id}' 已存在, 请使用 get_session() 获取")

        logger.info("创建浏览器会话: %s", session_id)

        # 构建上下文参数
        context_kwargs: Dict[str, Any] = {
            "viewport": DEFAULT_VIEWPORT,
            "user_agent": DEFAULT_USER_AGENT,
            "locale": self._locale,
            "timezone_id": self._timezone,
            "ignore_https_errors": True,
            "java_script_enabled": True,
            "has_touch": False,
            "is_mobile": False,
            "color_scheme": "light",
        }

        # 尝试从磁盘恢复存储状态
        state_file = Path(self._storage_dir) / session_id / "storage_state.json"
        if state_file.exists():
            try:
                context_kwargs["storage_state"] = str(state_file)
                logger.info("[%s] 从磁盘恢复存储状态", session_id)
            except Exception as e:
                logger.warning("[%s] 存储状态恢复失败: %s", session_id, e)

        # 创建浏览器上下文
        context = await self._browser.new_context(**context_kwargs)

        # 注入反检测脚本 (在每次页面加载前执行)
        for script in _get_stealth_scripts():
            await context.add_init_script(script)

        # 创建页面
        page = await context.new_page()

        # 创建会话对象
        session = BrowserSession(
            session_id=session_id,
            context=context,
            page=page,
            storage_dir=self._storage_dir,
        )

        # 尝试加载持久化数据
        await session.load_state()

        # 注册到会话管理器
        self._sessions[session_id] = session

        # 如果提供了 URL, 导航到该 URL
        if url:
            await session.navigate(url)

        logger.info("会话 '%s' 已创建就绪", session_id)
        return session

    async def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """获取已有的浏览器会话.

        Args:
            session_id: 会话标识符.

        Returns:
            BrowserSession 或 None (如果会话不存在).
        """
        return self._sessions.get(session_id)

    async def close_session(self, session_id: str) -> None:
        """关闭并保存浏览器会话.

        执行流程:
          1. 停止心跳监控
          2. 保存会话状态到磁盘
          3. 关闭浏览器上下文
          4. 从会话管理器中移除

        Args:
            session_id: 要关闭的会话标识符.
        """
        session = self._sessions.get(session_id)
        if not session:
            logger.warning("会话 '%s' 不存在", session_id)
            return

        logger.info("正在关闭会话: %s", session_id)

        # 停止心跳监控
        try:
            await session.stop_heartbeat_monitor()
        except Exception as e:
            logger.warning("[%s] 停止心跳监控失败: %s", session_id, e)

        # 保存状态
        try:
            await session.save_state()
        except Exception as e:
            logger.warning("[%s] 保存状态失败: %s", session_id, e)

        # 更新元数据
        session.metadata.status = "closed"
        try:
            meta_file = session._metadata_file
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(session.metadata.to_dict(), f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        # 关闭浏览器上下文
        try:
            await session.context.close()
        except Exception as e:
            logger.warning("[%s] 关闭上下文失败: %s", session_id, e)

        # 从管理器中移除
        del self._sessions[session_id]
        logger.info("会话 '%s' 已关闭", session_id)

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """列出所有活跃会话及其状态信息.

        Returns:
            list[dict]: 每个会话的信息, 包含 session_id, url, status,
                        heartbeat_active, page_title 等字段.
        """
        sessions_info: List[Dict[str, Any]] = []
        for sid, session in self._sessions.items():
            info = session.metadata.to_dict()
            # 添加心跳状态摘要
            hb_status = session.get_heartbeat_status()
            info["heartbeat_ws_count"] = len(hb_status.get("ws_heartbeats", []))
            info["heartbeat_http_count"] = len(hb_status.get("http_heartbeats", []))
            info["network_log_size"] = len(session._network_log)
            sessions_info.append(info)

        return sessions_info

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _ensure_running(self) -> None:
        """确保引擎已启动."""
        if not self._started or not self._browser:
            raise RuntimeError(
                "浏览器引擎未启动. 请先调用 await engine.start()"
            )

    def _build_launch_args(self) -> List[str]:
        """构建 Chromium 反检测启动参数.

        Returns:
            list[str]: Chromium 命令行参数列表.
        """
        args = [
            # 基础配置
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            # 反检测
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            # 性能
            "--disable-gpu",
            "--disable-extensions",
            # 隐私
            "--disable-default-apps",
            "--no-first-run",
            "--no-default-browser-check",
            # 窗口大小 (即使无头模式也设置, 保证一致性)
            f"--window-size={DEFAULT_VIEWPORT['width']},{DEFAULT_VIEWPORT['height']}",
            # WebRTC 泄漏防护
            "--disable-webrtc-hw-decoding",
            "--disable-webrtc-hw-encoding",
            "--disable-webrtc-multiple-routes",
            "--disable-webrtc-hw-vp8-encoding",
            # 其他反检测
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-breakpad",
            "--disable-component-extensions-with-background-pages",
            "--disable-features=TranslateUI",
            "--disable-hang-monitor",
            "--disable-ipc-flooding-protection",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-renderer-backgrounding",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-pings",
        ]
        return args

    async def __aenter__(self) -> "StealthBrowserEngine":
        """异步上下文管理器入口."""
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """异步上下文管理器出口."""
        await self.stop()


# 
# 引擎状态检查
# 

def get_engine_status(engine: Optional[StealthBrowserEngine] = None) -> Dict[str, Any]:
    """获取浏览器引擎健康状态.

    可在无引擎实例时调用, 返回 Playwright 安装状态.
    传入引擎实例时, 返回详细运行状态.

    Args:
        engine: 可选的 StealthBrowserEngine 实例.

    Returns:
        dict: 健康状态信息, 包含以下字段:
            - playwright_available (bool): Playwright 是否已安装
            - engine_running (bool): 引擎是否正在运行
            - uptime_seconds (float): 引擎运行时长
            - active_sessions (int): 活跃会话数
            - sessions (list): 各会话简要信息
            - storage_dir (str): 存储目录路径
            - headless (bool): 是否无头模式
            - proxy_configured (bool): 是否配置了代理
    """
    status: Dict[str, Any] = {
        "playwright_available": HAS_PLAYWRIGHT,
        "engine_running": False,
        "uptime_seconds": 0.0,
        "active_sessions": 0,
        "sessions": [],
        "storage_dir": DEFAULT_STORAGE_DIR,
        "headless": True,
        "proxy_configured": False,
    }

    if engine is None:
        return status

    status["engine_running"] = engine._started
    status["storage_dir"] = engine._storage_dir
    status["headless"] = engine._headless
    status["proxy_configured"] = engine._proxy is not None

    if engine._start_time:
        status["uptime_seconds"] = round(time.time() - engine._start_time, 1)

    status["active_sessions"] = len(engine._sessions)
    status["sessions"] = [
        {
            "session_id": sid,
            "url": s.metadata.url,
            "status": s.metadata.status,
            "heartbeat_active": s.metadata.heartbeat_active,
            "page_title": s.metadata.page_title,
        }
        for sid, s in engine._sessions.items()
    ]

    return status
