#!/usr/bin/env python3
"""
工具基类和注册系统

提供:
- BaseTool: 所有工具的抽象基类
- ToolResult: 统一的工具执行结果
- ToolRegistry: 工具注册和管理
- @tool 装饰器: 快速注册工具
"""

import asyncio
import logging
import time
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """工具分类"""
    NETWORK = "network"              # 网络侦察
    WEB = "web"                      # Web安全
    EXPLOIT = "exploit"              # 漏洞利用
    PASSWORD = "password"            # 密码攻击
    WIRELESS = "wireless"            # 无线攻击
    PWN = "pwn"                      # PWN/逆向
    OSINT = "osint"                  # 开源情报
    WORKFLOW = "workflow"            # 工作流/自动化
    AI = "ai"                        # AI辅助
    UTILITY = "utility"              # 辅助工具


class RiskLevel(Enum):
    """风险等级"""
    INFO = "info"           # 信息收集，无风险
    LOW = "low"             # 低风险
    MEDIUM = "medium"       # 中等风险
    HIGH = "high"           # 高风险
    CRITICAL = "critical"   # 关键风险（可能导致系统损坏）


@dataclass
class Finding:
    """发现项"""
    finding_type: str       # port, service, vulnerability, credential, file, flag
    value: str
    severity: str = "info"  # info, low, medium, high, critical
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.finding_type,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "details": self.details
        }


@dataclass
class ToolResult:
    """统一的工具执行结果"""

    # 基本状态
    success: bool
    tool_name: str = ""
    target: str = ""

    # 输出内容
    summary: str = ""                          # 一句话摘要
    findings: List[Finding] = field(default_factory=list)  # 结构化发现
    raw_output: str = ""                       # 原始输出

    # 建议
    next_steps: List[str] = field(default_factory=list)    # 建议的下一步
    recommended_tools: List[str] = field(default_factory=list)  # 推荐的工具

    # 元数据
    execution_time: float = 0.0
    cache_hit: bool = False
    error_message: str = ""

    # CTF相关
    flags_found: List[str] = field(default_factory=list)

    def add_finding(
        self,
        finding_type: str,
        value: str,
        severity: str = "info",
        **details
    ):
        """添加发现项"""
        self.findings.append(Finding(
            finding_type=finding_type,
            value=value,
            severity=severity,
            details=details
        ))

        # 自动检测Flag
        if finding_type == "flag":
            if value not in self.flags_found:
                self.flags_found.append(value)
        elif self._is_flag(value):
            # 从文本中提取实际的 flag
            extracted = self.extract_flags(value)
            for flag in extracted:
                if flag not in self.flags_found:
                    self.flags_found.append(flag)

    def _is_flag(self, text: str) -> bool:
        """检测是否为Flag格式"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'[a-f0-9]{32}',  # MD5
            r'[a-f0-9]{40}',  # SHA1
            r'[a-f0-9]{64}',  # SHA256
        ]
        for pattern in flag_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def extract_flags(self, text: str) -> List[str]:
        """从文本中提取Flag"""
        flags = []
        patterns = [
            r'(flag\{[^}]+\})',
            r'(FLAG\{[^}]+\})',
            r'(ctf\{[^}]+\})',
            r'(CTF\{[^}]+\})',
            r'(DASCTF\{[^}]+\})',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        return flags

    def suggest_next_step(self, step: str, tool: Optional[str] = None):
        """添加下一步建议"""
        self.next_steps.append(step)
        if tool:
            self.recommended_tools.append(tool)

    def get_ports(self) -> List[str]:
        """获取发现的端口"""
        return [f.value for f in self.findings if f.finding_type == "port"]

    def get_services(self) -> List[Dict[str, Any]]:
        """获取发现的服务"""
        return [f.to_dict() for f in self.findings if f.finding_type == "service"]

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """获取发现的漏洞"""
        return [f.to_dict() for f in self.findings if f.finding_type == "vulnerability"]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "tool": self.tool_name,
            "target": self.target,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": len(self.findings),
            "next_steps": self.next_steps,
            "recommended_tools": self.recommended_tools,
            "execution_time": self.execution_time,
            "cache_hit": self.cache_hit,
            "flags_found": self.flags_found,
            "error": self.error_message if not self.success else None
        }

    def to_mcp_response(self) -> Dict[str, Any]:
        """转换为MCP响应格式"""
        response = self.to_dict()

        # 添加raw_output用于详细分析
        if self.raw_output:
            response["raw_output"] = self.raw_output[:10000]  # 限制长度

        return response

    def __str__(self) -> str:
        """字符串表示"""
        status = "" if self.success else ""
        return f"[{status}] {self.tool_name}: {self.summary}"


class BaseTool(ABC):
    """
    工具基类

    所有安全工具都应继承此类并实现execute方法
    """

    # 工具元数据（子类需要重写）
    name: str = "base_tool"
    description: str = "Base tool description"
    category: ToolCategory = ToolCategory.UTILITY
    risk_level: RiskLevel = RiskLevel.INFO

    # 执行配置
    default_timeout: int = 300
    requires_root: bool = False

    # 依赖工具
    dependencies: List[str] = []

    def __init__(self):
        """初始化工具"""
        self.logger = logging.getLogger(f"tool.{self.name}")

    @abstractmethod
    async def execute(self, target: str, **kwargs) -> ToolResult:
        """
        执行工具

        Args:
            target: 目标地址
            **kwargs: 工具特定参数

        Returns:
            ToolResult对象
        """
        pass

    async def run(self, target: str, **kwargs) -> ToolResult:
        """
        运行工具（带计时和错误处理）

        Args:
            target: 目标
            **kwargs: 参数

        Returns:
            ToolResult
        """
        start_time = time.time()

        try:
            self.logger.info(f"执行 {self.name} 目标: {target}")
            result = await self.execute(target, **kwargs)
            result.tool_name = self.name
            result.target = target
            result.execution_time = time.time() - start_time

            # 自动生成摘要（如果未设置）
            if not result.summary:
                result.summary = self._generate_summary(result)

            # 自动推荐下一步
            if not result.next_steps:
                result.next_steps = self._suggest_next_steps(result)

            self.logger.info(f"完成 {self.name}: {result.summary}")
            return result

        except Exception as e:
            self.logger.error(f"执行错误 {self.name}: {e}")
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=target,
                error_message=str(e),
                execution_time=time.time() - start_time
            )

    def _generate_summary(self, result: ToolResult) -> str:
        """生成结果摘要"""
        if not result.success:
            return f"执行失败: {result.error_message}"

        findings_count = len(result.findings)
        if findings_count == 0:
            return "未发现任何内容"

        # 按类型统计
        type_counts = {}
        for f in result.findings:
            type_counts[f.finding_type] = type_counts.get(f.finding_type, 0) + 1

        parts = [f"{count}个{ftype}" for ftype, count in type_counts.items()]
        return f"发现 {', '.join(parts)}"

    def _suggest_next_steps(self, result: ToolResult) -> List[str]:
        """根据结果推荐下一步"""
        suggestions = []

        # 基于发现类型推荐
        for finding in result.findings:
            if finding.finding_type == "port":
                if "80" in finding.value or "443" in finding.value:
                    suggestions.append("发现Web端口，建议使用 gobuster_scan 扫描目录")
                elif "22" in finding.value:
                    suggestions.append("发现SSH端口，可尝试 hydra_attack 进行弱口令测试")
                elif "3306" in finding.value:
                    suggestions.append("发现MySQL端口，可尝试 sqlmap_scan 进行SQL注入测试")

            elif finding.finding_type == "vulnerability":
                if finding.severity in ["high", "critical"]:
                    suggestions.append(f"发现高危漏洞 {finding.value}，建议使用 searchsploit_search 查找利用代码")

        return suggestions[:5]  # 最多5条建议

    def validate_target(self, target: str) -> bool:
        """验证目标格式"""
        # 基本验证，子类可以重写
        return bool(target and target.strip())

    def get_info(self) -> Dict[str, Any]:
        """获取工具信息"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk_level": self.risk_level.value,
            "timeout": self.default_timeout,
            "requires_root": self.requires_root,
            "dependencies": self.dependencies
        }


class ToolRegistry:
    """
    工具注册表

    管理所有已注册的工具，提供查找和执行功能
    """

    _instance: Optional['ToolRegistry'] = None

    def __new__(cls):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._tools: Dict[str, Type[BaseTool]] = {}
        self._instances: Dict[str, BaseTool] = {}
        self._categories: Dict[ToolCategory, List[str]] = {cat: [] for cat in ToolCategory}
        self._initialized = True

        logger.info("ToolRegistry 初始化完成")

    def register(self, tool_class: Type[BaseTool]) -> Type[BaseTool]:
        """
        注册工具类

        Args:
            tool_class: 工具类

        Returns:
            工具类（用于装饰器链）
        """
        name = tool_class.name

        if name in self._tools:
            logger.warning(f"工具 {name} 已存在，将被覆盖")

        self._tools[name] = tool_class
        self._categories[tool_class.category].append(name)

        logger.debug(f"注册工具: {name} ({tool_class.category.value})")
        return tool_class

    def get(self, name: str) -> Optional[BaseTool]:
        """
        获取工具实例

        Args:
            name: 工具名称

        Returns:
            工具实例或None
        """
        if name not in self._tools:
            return None

        # 懒加载实例
        if name not in self._instances:
            self._instances[name] = self._tools[name]()

        return self._instances[name]

    def get_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """获取指定分类的所有工具"""
        tools = []
        for name in self._categories.get(category, []):
            tool = self.get(name)
            if tool:
                tools.append(tool)
        return tools

    def list_tools(
        self,
        category: Optional[ToolCategory] = None,
        risk_level: Optional[RiskLevel] = None
    ) -> List[Dict[str, Any]]:
        """列出工具"""
        tools = []

        for name, tool_class in self._tools.items():
            if category and tool_class.category != category:
                continue
            if risk_level and tool_class.risk_level != risk_level:
                continue

            tool = self.get(name)
            if tool:
                tools.append(tool.get_info())

        return tools

    def search(self, keyword: str) -> List[Dict[str, Any]]:
        """搜索工具"""
        keyword = keyword.lower()
        results = []

        for name, tool_class in self._tools.items():
            if keyword in name.lower() or keyword in tool_class.description.lower():
                tool = self.get(name)
                if tool:
                    results.append(tool.get_info())

        return results

    async def execute(self, name: str, target: str, **kwargs) -> ToolResult:
        """
        执行工具

        Args:
            name: 工具名称
            target: 目标
            **kwargs: 工具参数

        Returns:
            ToolResult
        """
        tool = self.get(name)

        if not tool:
            return ToolResult(
                success=False,
                tool_name=name,
                target=target,
                error_message=f"工具 {name} 未找到"
            )

        return await tool.run(target, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        category_counts = {cat.value: len(tools) for cat, tools in self._categories.items()}

        return {
            "total_tools": len(self._tools),
            "loaded_instances": len(self._instances),
            "by_category": category_counts
        }


def tool(
    name: Optional[str] = None,
    category: ToolCategory = ToolCategory.UTILITY,
    description: str = "",
    risk_level: RiskLevel = RiskLevel.INFO,
    timeout: int = 300
):
    """
    工具装饰器

    使用方法:

    @tool(name="my_tool", category=ToolCategory.WEB)
    class MyTool(BaseTool):
        async def execute(self, target, **kwargs):
            ...

    或者用于函数:

    @tool(name="my_scan")
    async def my_scan(target: str) -> ToolResult:
        ...
    """
    def decorator(cls_or_func: Union[Type[BaseTool], Callable]):
        registry = get_registry()

        if isinstance(cls_or_func, type) and issubclass(cls_or_func, BaseTool):
            # 类装饰器
            if name:
                cls_or_func.name = name
            if description:
                cls_or_func.description = description
            cls_or_func.category = category
            cls_or_func.risk_level = risk_level
            cls_or_func.default_timeout = timeout

            registry.register(cls_or_func)
            return cls_or_func
        else:
            # 函数装饰器 - 创建包装类
            func = cls_or_func
            tool_name = name or func.__name__
            tool_desc = description or func.__doc__ or ""
            # 保存外部变量到本地变量以避免作用域问题
            _category = category
            _risk_level = risk_level
            _timeout = timeout
            _func = func  # 捕获函数引用

            # 使用闭包创建一个工厂函数来定义类
            def make_tool_class():
                class FunctionTool(BaseTool):
                    name = tool_name
                    description = tool_desc
                    category = _category
                    risk_level = _risk_level
                    default_timeout = _timeout

                    async def execute(self, target: str, **kwargs) -> ToolResult:
                        if asyncio.iscoroutinefunction(_func):
                            return await _func(target, **kwargs)
                        else:
                            return _func(target, **kwargs)

                return FunctionTool

            FunctionToolClass = make_tool_class()
            registry.register(FunctionToolClass)

            @wraps(func)
            async def wrapper(target: str, **kwargs) -> ToolResult:
                return await registry.execute(tool_name, target, **kwargs)

            return wrapper

    return decorator


# 全局注册表
_global_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """获取全局工具注册表"""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry
