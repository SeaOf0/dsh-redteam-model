#!/usr/bin/env python3
"""
CTF POC 扫描引擎 v1.0

核心功能:
- YAML格式POC定义和执行
- 并发POC扫描
- 步骤序列执行
- 提取器和匹配器支持
- 会话数据传递

作者: SeaOf0
"""

import os
import re
import yaml
import json
import asyncio
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from threading import Lock
from datetime import datetime

logger = logging.getLogger(__name__)


class POCSeverity(Enum):
    """POC严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MatcherType(Enum):
    """匹配器类型"""
    WORD = "word"
    STATUS = "status"
    REGEX = "regex"
    BINARY = "binary"
    SIZE = "size"
    HEADER = "header"


class ExtractorType(Enum):
    """提取器类型"""
    REGEX = "regex"
    XPATH = "xpath"
    JSON = "json"
    HEADER = "header"


@dataclass
class POCRequest:
    """POC请求定义"""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    query: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30


@dataclass
class POCMatcher:
    """POC匹配器"""
    type: MatcherType
    values: List[Any]
    condition: str = "and"  # "and" or "or"
    negative: bool = False  # 反向匹配


@dataclass
class POCExtractor:
    """POC提取器"""
    type: ExtractorType
    name: str
    pattern: str
    group: int = 0


@dataclass
class POCStep:
    """POC执行步骤"""
    request: POCRequest
    matchers: List[POCMatcher] = field(default_factory=list)
    extractors: List[POCExtractor] = field(default_factory=list)


@dataclass
class POCDefinition:
    """POC定义"""
    id: str
    name: str
    description: str = ""
    severity: POCSeverity = POCSeverity.MEDIUM
    author: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    steps: List[POCStep] = field(default_factory=list)
    post_exploitation: List[Dict] = field(default_factory=list)


@dataclass
class POCResult:
    """POC执行结果"""
    poc_id: str
    poc_name: str
    target_url: str
    vulnerable: bool
    severity: POCSeverity
    description: str = ""
    matched_step: int = 0
    requests: List[Dict] = field(default_factory=list)
    responses: List[Dict] = field(default_factory=list)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class HTTPClient:
    """HTTP客户端 - 可被替换为实际的请求库"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session_cookies: Dict[str, str] = {}

    async def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        body: str = "",
        params: Dict[str, str] = None,
        timeout: int = None
    ) -> Dict[str, Any]:
        """发送HTTP请求"""
        try:
            import aiohttp

            timeout_val = timeout or self.timeout
            async with aiohttp.ClientSession() as session:
                # 合并session cookies
                request_headers = headers or {}
                if self.session_cookies:
                    cookie_str = "; ".join([f"{k}={v}" for k, v in self.session_cookies.items()])
                    request_headers["Cookie"] = cookie_str

                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    data=body if body else None,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=timeout_val),
                    ssl=False
                ) as response:
                    content = await response.text()

                    # 保存响应cookies
                    for cookie in response.cookies.values():
                        self.session_cookies[cookie.key] = cookie.value

                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "content": content,
                        "url": str(response.url)
                    }
        except ImportError:
            # 回退到同步请求
            return self._sync_request(method, url, headers, body, params, timeout)
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "content": "",
                "url": url,
                "error": str(e)
            }

    def _sync_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        body: str = "",
        params: Dict[str, str] = None,
        timeout: int = None
    ) -> Dict[str, Any]:
        """同步HTTP请求回退"""
        try:
            import requests as req

            timeout_val = timeout or self.timeout
            response = req.request(
                method=method,
                url=url,
                headers=headers,
                data=body if body else None,
                params=params,
                timeout=timeout_val,
                verify=False
            )

            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "content": response.text,
                "url": response.url
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "content": "",
                "url": url,
                "error": str(e)
            }


class POCParser:
    """POC解析器 - 支持YAML和Nuclei格式"""

    @staticmethod
    def parse_yaml(content: str) -> Optional[POCDefinition]:
        """解析YAML格式POC"""
        try:
            data = yaml.safe_load(content)

            # 生成POC ID
            poc_id = data.get("id", hashlib.md5(content.encode()).hexdigest()[:8])

            # 解析严重程度
            severity_str = data.get("severity", "medium").lower()
            severity = POCSeverity(severity_str) if severity_str in [s.value for s in POCSeverity] else POCSeverity.MEDIUM

            # 解析步骤
            steps = []
            for req_seq in data.get("requests", []):
                if "steps" in req_seq:
                    for step_data in req_seq["steps"]:
                        step = POCParser._parse_step(step_data)
                        if step:
                            steps.append(step)

            # 解析后利用
            post_exploitation = []
            for req_seq in data.get("requests", []):
                if "post" in req_seq:
                    post_exploitation = req_seq["post"]

            return POCDefinition(
                id=poc_id,
                name=data.get("name", "Unknown POC"),
                description=data.get("description", ""),
                severity=severity,
                author=data.get("author", ""),
                tags=data.get("tags", []),
                references=data.get("references", []),
                steps=steps,
                post_exploitation=post_exploitation
            )
        except Exception as e:
            logger.error(f"POC解析失败: {e}")
            return None

    @staticmethod
    def _parse_step(step_data: Dict) -> Optional[POCStep]:
        """解析单个步骤"""
        try:
            # 解析请求
            request = POCRequest(
                method=step_data.get("method", "GET").upper(),
                path=step_data.get("path", "/"),
                headers=step_data.get("headers", {}),
                body=step_data.get("body", ""),
                query=step_data.get("query", {})
            )

            # 解析匹配器
            matchers = []
            for matcher_data in step_data.get("matchers", []):
                matcher_type_str = matcher_data.get("type", "word").lower()
                matcher_type = MatcherType(matcher_type_str) if matcher_type_str in [m.value for m in MatcherType] else MatcherType.WORD

                values = []
                if matcher_type == MatcherType.WORD:
                    values = matcher_data.get("words", [])
                elif matcher_type == MatcherType.STATUS:
                    values = matcher_data.get("status", [])
                elif matcher_type == MatcherType.REGEX:
                    values = matcher_data.get("regex", [])

                matchers.append(POCMatcher(
                    type=matcher_type,
                    values=values,
                    condition=matcher_data.get("condition", "and"),
                    negative=matcher_data.get("negative", False)
                ))

            # 解析提取器
            extractors = []
            for extractor_data in step_data.get("extractors", []):
                extractor_type_str = extractor_data.get("type", "regex").lower()
                extractor_type = ExtractorType(extractor_type_str) if extractor_type_str in [e.value for e in ExtractorType] else ExtractorType.REGEX

                patterns = extractor_data.get("regex", []) or extractor_data.get("pattern", [])
                for pattern in patterns if isinstance(patterns, list) else [patterns]:
                    extractors.append(POCExtractor(
                        type=extractor_type,
                        name=extractor_data.get("name", "extracted_value"),
                        pattern=pattern,
                        group=extractor_data.get("group", 0)
                    ))

            return POCStep(
                request=request,
                matchers=matchers,
                extractors=extractors
            )
        except Exception as e:
            logger.error(f"步骤解析失败: {e}")
            return None


class POCExecutor:
    """POC执行器"""

    def __init__(self, http_client: HTTPClient = None, max_workers: int = 5):
        self.http_client = http_client or HTTPClient()
        self.max_workers = max_workers
        self.results_lock = Lock()

    async def execute_poc(
        self,
        poc: POCDefinition,
        target_url: str,
        session_data: Dict[str, Any] = None
    ) -> POCResult:
        """执行单个POC"""
        session_data = session_data or {}
        all_requests = []
        all_responses = []

        logger.debug(f"执行POC: {poc.name} 针对目标: {target_url}")

        for step_index, step in enumerate(poc.steps):
            try:
                # 执行步骤
                step_result = await self._execute_step(step, target_url, session_data)

                all_requests.append(step_result["request"])
                all_responses.append(step_result["response"])

                # 更新会话数据
                if step_result.get("extracted_data"):
                    session_data.update(step_result["extracted_data"])

                # 检查是否匹配漏洞
                if step_result["matched"]:
                    return POCResult(
                        poc_id=poc.id,
                        poc_name=poc.name,
                        target_url=target_url,
                        vulnerable=True,
                        severity=poc.severity,
                        description=poc.description,
                        matched_step=step_index + 1,
                        requests=all_requests,
                        responses=all_responses,
                        extracted_data=session_data
                    )

            except Exception as e:
                logger.error(f"步骤 {step_index + 1} 执行失败: {e}")
                continue

        # 未发现漏洞
        return POCResult(
            poc_id=poc.id,
            poc_name=poc.name,
            target_url=target_url,
            vulnerable=False,
            severity=poc.severity,
            description=poc.description,
            requests=all_requests,
            responses=all_responses
        )

    async def _execute_step(
        self,
        step: POCStep,
        target_url: str,
        session_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行单个步骤"""
        # 变量替换
        path = self._replace_variables(step.request.path, session_data)
        body = self._replace_variables(step.request.body, session_data)
        headers = {k: self._replace_variables(v, session_data) for k, v in step.request.headers.items()}
        query = {k: self._replace_variables(v, session_data) for k, v in step.request.query.items()}

        # 构建完整URL
        full_url = urljoin(target_url, path)
        if query:
            from urllib.parse import urlencode
            full_url = f"{full_url}?{urlencode(query)}"

        # 设置默认headers
        default_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; KaliMCP-POCScanner/1.0)",
            "Accept": "*/*",
            "Connection": "close"
        }
        default_headers.update(headers)

        # 发送请求
        response = await self.http_client.request(
            method=step.request.method,
            url=full_url,
            headers=default_headers,
            body=body,
            timeout=step.request.timeout
        )

        # 处理提取器
        extracted_data = self._process_extractors(step.extractors, response.get("content", ""))

        # 检查匹配器
        matched = self._check_matchers(step.matchers, response)

        return {
            "request": {
                "method": step.request.method,
                "url": full_url,
                "headers": default_headers,
                "body": body
            },
            "response": response,
            "extracted_data": extracted_data,
            "matched": matched
        }

    def _replace_variables(self, text: str, session_data: Dict[str, Any]) -> str:
        """替换变量"""
        if not text:
            return text

        result = text
        for key, value in session_data.items():
            result = result.replace(f"{{{key}}}", str(value))

        return result

    def _process_extractors(
        self,
        extractors: List[POCExtractor],
        content: str
    ) -> Dict[str, Any]:
        """处理提取器"""
        extracted_data = {}

        for extractor in extractors:
            if extractor.type == ExtractorType.REGEX:
                match = re.search(extractor.pattern, content, re.IGNORECASE | re.DOTALL)
                if match:
                    try:
                        value = match.group(extractor.group)
                        extracted_data[extractor.name] = value
                        logger.debug(f"提取到 {extractor.name}: {value}")
                    except IndexError:
                        pass

            elif extractor.type == ExtractorType.JSON:
                try:
                    data = json.loads(content)
                    # 支持简单的JSON路径
                    parts = extractor.pattern.split(".")
                    value = data
                    for part in parts:
                        if isinstance(value, dict):
                            value = value.get(part)
                        elif isinstance(value, list) and part.isdigit():
                            value = value[int(part)]
                        else:
                            value = None
                            break
                    if value is not None:
                        extracted_data[extractor.name] = value
                except:
                    pass

        return extracted_data

    def _check_matchers(
        self,
        matchers: List[POCMatcher],
        response: Dict[str, Any]
    ) -> bool:
        """检查匹配器"""
        if not matchers:
            # 默认检查状态码
            return response.get("status", 0) == 200

        results = []
        content = response.get("content", "")
        status = response.get("status", 0)
        headers = response.get("headers", {})

        for matcher in matchers:
            matched = False

            if matcher.type == MatcherType.WORD:
                if matcher.condition == "and":
                    matched = all(word in content for word in matcher.values)
                else:
                    matched = any(word in content for word in matcher.values)

            elif matcher.type == MatcherType.STATUS:
                matched = status in matcher.values

            elif matcher.type == MatcherType.REGEX:
                if matcher.condition == "and":
                    matched = all(re.search(pattern, content, re.IGNORECASE) for pattern in matcher.values)
                else:
                    matched = any(re.search(pattern, content, re.IGNORECASE) for pattern in matcher.values)

            elif matcher.type == MatcherType.HEADER:
                for header_check in matcher.values:
                    if ":" in header_check:
                        header_name, header_value = header_check.split(":", 1)
                        if headers.get(header_name.strip(), "").strip() == header_value.strip():
                            matched = True
                            break

            # 处理反向匹配
            if matcher.negative:
                matched = not matched

            results.append((matched, matcher.condition))

        # 计算最终结果
        if not results:
            return False

        # 检查是否有OR条件满足
        for matched, condition in results:
            if condition == "or" and matched:
                return True

        # 检查所有AND条件
        and_results = [matched for matched, condition in results if condition != "or"]
        return all(and_results) if and_results else False


class POCScanner:
    """POC扫描器 - 并发执行多个POC"""

    def __init__(
        self,
        poc_dir: str = None,
        max_workers: int = 5,
        http_timeout: int = 30
    ):
        self.poc_dir = poc_dir
        self.max_workers = max_workers
        self.http_client = HTTPClient(timeout=http_timeout)
        self.executor = POCExecutor(self.http_client, max_workers)
        self.poc_cache: Dict[str, POCDefinition] = {}
        self.results_lock = Lock()

    def load_pocs(self, poc_dir: str = None) -> List[POCDefinition]:
        """加载POC文件"""
        poc_dir = poc_dir or self.poc_dir
        if not poc_dir or not os.path.exists(poc_dir):
            logger.warning(f"POC目录不存在: {poc_dir}")
            return []

        pocs = []
        for filename in os.listdir(poc_dir):
            if filename.endswith(('.yaml', '.yml')):
                filepath = os.path.join(poc_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()

                    poc = POCParser.parse_yaml(content)
                    if poc:
                        poc.id = filename.rsplit('.', 1)[0]  # 使用文件名作为ID
                        pocs.append(poc)
                        self.poc_cache[poc.id] = poc
                        logger.debug(f"加载POC: {poc.name}")
                except Exception as e:
                    logger.error(f"加载POC {filename} 失败: {e}")

        logger.info(f"共加载 {len(pocs)} 个POC")
        return pocs

    async def scan(
        self,
        target_url: str,
        pocs: List[POCDefinition] = None,
        poc_ids: List[str] = None,
        tags: List[str] = None,
        severity_filter: List[POCSeverity] = None,
        callback: Callable[[POCResult], None] = None
    ) -> List[POCResult]:
        """执行POC扫描"""
        # 确定要执行的POC
        if pocs is None:
            pocs = list(self.poc_cache.values())

        if poc_ids:
            pocs = [p for p in pocs if p.id in poc_ids]

        if tags:
            pocs = [p for p in pocs if any(t in p.tags for t in tags)]

        if severity_filter:
            pocs = [p for p in pocs if p.severity in severity_filter]

        if not pocs:
            logger.warning("没有可执行的POC")
            return []

        logger.info(f"开始扫描目标 {target_url}, 共 {len(pocs)} 个POC")

        results = []
        vulnerabilities = []

        # 并发执行POC
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            # 创建事件循环
            loop = asyncio.get_event_loop()

            futures = {
                pool.submit(
                    lambda p=poc: loop.run_until_complete(self.executor.execute_poc(p, target_url))
                ): poc
                for poc in pocs
            }

            for future in as_completed(futures):
                poc = futures[future]
                try:
                    result = future.result()

                    with self.results_lock:
                        results.append(result)

                        if result.vulnerable:
                            vulnerabilities.append(result)
                            logger.info(f"发现漏洞: {result.poc_name}")

                        if callback:
                            callback(result)

                except Exception as e:
                    logger.error(f"POC {poc.name} 执行异常: {e}")
                    results.append(POCResult(
                        poc_id=poc.id,
                        poc_name=poc.name,
                        target_url=target_url,
                        vulnerable=False,
                        severity=poc.severity,
                        error=str(e)
                    ))

        # 统计结果
        vuln_count = len(vulnerabilities)
        logger.info(f"扫描完成，共测试 {len(pocs)} 个POC，发现 {vuln_count} 个漏洞")

        return results

    def scan_sync(
        self,
        target_url: str,
        **kwargs
    ) -> List[POCResult]:
        """同步扫描接口"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.scan(target_url, **kwargs))
        finally:
            loop.close()


class POCManager:
    """POC管理器 - 统一管理POC的加载、缓存和执行"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.scanners: Dict[str, POCScanner] = {}
        self.default_poc_dirs: List[str] = []
        self.custom_pocs: Dict[str, POCDefinition] = {}

    def register_poc_dir(self, name: str, path: str, max_workers: int = 5) -> POCScanner:
        """注册POC目录"""
        scanner = POCScanner(poc_dir=path, max_workers=max_workers)
        scanner.load_pocs()
        self.scanners[name] = scanner
        self.default_poc_dirs.append(path)
        logger.info(f"注册POC目录: {name} -> {path}")
        return scanner

    def register_poc(self, poc: POCDefinition):
        """注册单个POC"""
        self.custom_pocs[poc.id] = poc
        logger.info(f"注册自定义POC: {poc.name}")

    def register_poc_from_yaml(self, content: str) -> Optional[POCDefinition]:
        """从YAML内容注册POC"""
        poc = POCParser.parse_yaml(content)
        if poc:
            self.register_poc(poc)
        return poc

    def get_all_pocs(self) -> List[POCDefinition]:
        """获取所有POC"""
        pocs = list(self.custom_pocs.values())
        for scanner in self.scanners.values():
            pocs.extend(scanner.poc_cache.values())
        return pocs

    async def scan_all(
        self,
        target_url: str,
        **kwargs
    ) -> List[POCResult]:
        """使用所有注册的POC扫描"""
        all_pocs = self.get_all_pocs()

        if not all_pocs:
            logger.warning("没有注册的POC")
            return []

        # 创建临时扫描器
        scanner = POCScanner(max_workers=kwargs.get("max_workers", 5))
        scanner.poc_cache = {p.id: p for p in all_pocs}

        return await scanner.scan(target_url, pocs=all_pocs, **kwargs)


# 便捷函数
def get_poc_manager() -> POCManager:
    """获取POC管理器单例"""
    return POCManager()


def create_poc_from_yaml(yaml_content: str) -> Optional[POCDefinition]:
    """从YAML创建POC"""
    return POCParser.parse_yaml(yaml_content)


async def quick_poc_scan(
    target_url: str,
    poc_yaml: str = None,
    poc_dir: str = None,
    max_workers: int = 5
) -> List[POCResult]:
    """快速POC扫描"""
    scanner = POCScanner(poc_dir=poc_dir, max_workers=max_workers)

    if poc_yaml:
        poc = create_poc_from_yaml(poc_yaml)
        if poc:
            return await scanner.scan(target_url, pocs=[poc])

    if poc_dir:
        scanner.load_pocs()

    return await scanner.scan(target_url)


# 导出
__all__ = [
    "POCSeverity",
    "MatcherType",
    "ExtractorType",
    "POCRequest",
    "POCMatcher",
    "POCExtractor",
    "POCStep",
    "POCDefinition",
    "POCResult",
    "HTTPClient",
    "POCParser",
    "POCExecutor",
    "POCScanner",
    "POCManager",
    "get_poc_manager",
    "create_poc_from_yaml",
    "quick_poc_scan",
]
