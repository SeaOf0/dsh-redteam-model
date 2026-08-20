#!/usr/bin/env python3
"""
Kali MCP ReAct 思考引擎 v2.1

 ReAct (Reasoning + Acting) 模式:
- Thought: 分析当前情况，思考下一步
- Action: 选择要执行的工具
- Observation: 观察工具执行结果
- 循环直到达成目标或达到最大迭代次数

适配场景:
- 安全测试的智能决策
- CTF 题目的自动化求解
- 渗透测试的自适应攻击
"""

import asyncio
import re
import json
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


# ============ 步骤类型 ============

class StepType(str, Enum):
    """ReAct 步骤类型"""
    THOUGHT = "thought"
    ACTION = "action"
    OBSERVATION = "observation"
    FINAL_ANSWER = "final_answer"
    ERROR = "error"


# ============ 步骤数据结构 ============

@dataclass
class ReActStep:
    """ReAct 单步骤"""
    step_type: StepType
    content: str
    timestamp: float = field(default_factory=time.time)

    # Action 特定字段
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None

    # Observation 特定字段
    observation: Optional[str] = None
    tool_duration_ms: Optional[int] = None

    # 元数据
    iteration: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_type": self.step_type.value,
            "content": self.content,
            "timestamp": self.timestamp,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation,
            "tool_duration_ms": self.tool_duration_ms,
            "iteration": self.iteration,
            "metadata": self.metadata,
        }


# ============ 执行结果 ============

@dataclass
class ReActResult:
    """ReAct 执行结果"""
    success: bool
    final_answer: Optional[str] = None
    error: Optional[str] = None

    # 执行统计
    iterations: int = 0
    tool_calls: int = 0
    total_duration_ms: int = 0

    # 中间步骤
    steps: List[ReActStep] = field(default_factory=list)

    # 发现的结果
    findings: List[Dict[str, Any]] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "final_answer": self.final_answer,
            "error": self.error,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "total_duration_ms": self.total_duration_ms,
            "steps": [s.to_dict() for s in self.steps],
            "findings": self.findings,
            "flags": self.flags,
            "metadata": self.metadata,
        }


# ============ 任务交接协议 ============

@dataclass
class TaskHandoff:
    """
    任务交接协议 - 在多阶段攻击中传递上下文

    用于:
    - 侦察 -> 分析 的信息传递
    - 分析 -> 利用 的漏洞传递
    - 各阶段的状态同步
    """
    from_phase: str
    to_phase: str

    # 工作摘要
    summary: str
    work_completed: List[str] = field(default_factory=list)

    # 关键发现
    key_findings: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

    # 建议和关注点
    suggested_actions: List[Dict[str, Any]] = field(default_factory=list)
    attention_points: List[str] = field(default_factory=list)
    priority_areas: List[str] = field(default_factory=list)

    # 目标信息
    target_info: Dict[str, Any] = field(default_factory=dict)

    # 置信度
    confidence: float = 0.8

    # 时间戳
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_phase": self.from_phase,
            "to_phase": self.to_phase,
            "summary": self.summary,
            "work_completed": self.work_completed,
            "key_findings": self.key_findings,
            "insights": self.insights,
            "suggested_actions": self.suggested_actions,
            "attention_points": self.attention_points,
            "priority_areas": self.priority_areas,
            "target_info": self.target_info,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_prompt_context(self) -> str:
        """转换为 LLM 可理解的上下文格式"""
        lines = [
            f"## 来自 {self.from_phase} 阶段的任务交接",
            "",
            f"### 工作摘要",
            self.summary,
            "",
        ]

        if self.work_completed:
            lines.append("### 已完成的工作")
            for work in self.work_completed:
                lines.append(f"- {work}")
            lines.append("")

        if self.key_findings:
            lines.append("### 关键发现")
            for i, finding in enumerate(self.key_findings[:15], 1):
                severity = finding.get("severity", "medium")
                title = finding.get("title", "Unknown")
                lines.append(f"{i}. [{severity.upper()}] {title}")
                if finding.get("description"):
                    lines.append(f"   描述: {finding['description'][:100]}")
            lines.append("")

        if self.insights:
            lines.append("### 洞察和分析")
            for insight in self.insights:
                lines.append(f"- {insight}")
            lines.append("")

        if self.suggested_actions:
            lines.append("### 建议的下一步行动")
            for action in self.suggested_actions:
                action_type = action.get("type", "general")
                description = action.get("description", "")
                priority = action.get("priority", "medium")
                lines.append(f"- [{priority.upper()}] {action_type}: {description}")
            lines.append("")

        if self.attention_points:
            lines.append("###  需要特别关注")
            for point in self.attention_points:
                lines.append(f"- {point}")
            lines.append("")

        if self.target_info:
            lines.append("### 目标信息")
            for key, value in self.target_info.items():
                lines.append(f"- {key}: {value}")

        return "\n".join(lines)


# ============ ReAct 解析器 ============

class ReActParser:
    """解析 LLM 输出中的 Thought/Action/Action Input"""

    # 正则表达式模式
    THOUGHT_PATTERN = re.compile(
        r'(?:\*\*)?Thought:(?:\*\*)?\s*(.*?)(?=(?:\*\*)?Action:|(?:\*\*)?Final Answer:|$)',
        re.DOTALL | re.IGNORECASE
    )
    ACTION_PATTERN = re.compile(
        r'(?:\*\*)?Action:(?:\*\*)?\s*(\w+)',
        re.IGNORECASE
    )
    ACTION_INPUT_PATTERN = re.compile(
        r'(?:\*\*)?Action Input:(?:\*\*)?\s*(.*?)(?=(?:\*\*)?Thought:|(?:\*\*)?Action:|(?:\*\*)?Observation:|$)',
        re.DOTALL | re.IGNORECASE
    )
    FINAL_ANSWER_PATTERN = re.compile(
        r'(?:\*\*)?Final Answer:(?:\*\*)?\s*(.*)',
        re.DOTALL | re.IGNORECASE
    )

    @classmethod
    def parse(cls, response: str) -> ReActStep:
        """
        解析 LLM 响应

        Args:
            response: LLM 的原始响应

        Returns:
            解析后的 ReActStep
        """
        # 预处理: 移除 Markdown 格式标记
        cleaned = response
        cleaned = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned)
        cleaned = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned)
        cleaned = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned)
        cleaned = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned)
        cleaned = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned)

        # 尝试提取 Final Answer
        final_match = cls.FINAL_ANSWER_PATTERN.search(cleaned)
        if final_match:
            return ReActStep(
                step_type=StepType.FINAL_ANSWER,
                content=final_match.group(1).strip(),
            )

        # 提取 Thought
        thought = ""
        thought_match = cls.THOUGHT_PATTERN.search(cleaned)
        if thought_match:
            thought = thought_match.group(1).strip()

        # 提取 Action
        action = None
        action_match = cls.ACTION_PATTERN.search(cleaned)
        if action_match:
            action = action_match.group(1).strip()

            # 如果没有 Thought，用 Action 之前的内容作为思考
            if not thought:
                action_pos = cleaned.find('Action:')
                if action_pos > 0:
                    thought = cleaned[:action_pos].strip()
                    thought = re.sub(r'^Thought:\s*', '', thought, flags=re.IGNORECASE)

        # 提取 Action Input
        action_input = None
        input_match = cls.ACTION_INPUT_PATTERN.search(cleaned)
        if input_match:
            input_text = input_match.group(1).strip()
            action_input = cls._parse_json_input(input_text)

        # 构建步骤
        if action:
            return ReActStep(
                step_type=StepType.ACTION,
                content=thought,
                action=action,
                action_input=action_input or {},
            )
        elif thought:
            return ReActStep(
                step_type=StepType.THOUGHT,
                content=thought,
            )
        else:
            # 无法解析
            return ReActStep(
                step_type=StepType.ERROR,
                content=f"无法解析响应: {response[:200]}...",
                metadata={"raw_response": response},
            )

    @staticmethod
    def _parse_json_input(text: str) -> Optional[Dict[str, Any]]:
        """解析 JSON 格式的 Action Input"""
        text = text.strip()

        # 移除 markdown 代码块标记
        if text.startswith('```'):
            text = re.sub(r'^```\w*\n?', '', text)
            text = re.sub(r'\n?```$', '', text)
            text = text.strip()

        # 尝试解析 JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 尝试修复常见的 JSON 错误
        try:
            # 单引号替换为双引号
            fixed = text.replace("'", '"')
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        # 尝试提取 JSON 对象
        json_match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # 返回空字典，让工具使用默认参数
        logger.warning(f"Failed to parse Action Input: {text[:100]}")
        return {}


# ============ 工具执行器接口 ============

class ToolExecutor(ABC):
    """工具执行器抽象接口"""

    @abstractmethod
    async def execute(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """
        执行工具

        Args:
            tool_name: 工具名称
            tool_input: 工具参数

        Returns:
            工具执行结果
        """
        pass

    @abstractmethod
    def get_available_tools(self) -> List[str]:
        """获取可用工具列表"""
        pass

    @abstractmethod
    def get_tool_description(self, tool_name: str) -> str:
        """获取工具描述"""
        pass


# ============ 默认工具执行器 ============

class DefaultToolExecutor(ToolExecutor):
    """默认工具执行器 - 使用 Kali MCP 工具"""

    def __init__(self, tools: Dict[str, Callable]):
        """
        初始化

        Args:
            tools: 工具字典 {工具名: 工具函数}
        """
        self.tools = tools

    async def execute(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """执行工具"""
        if tool_name not in self.tools:
            return f"错误: 工具 '{tool_name}' 不存在。可用工具: {list(self.tools.keys())}"

        try:
            tool_func = self.tools[tool_name]

            # 执行工具
            if asyncio.iscoroutinefunction(tool_func):
                result = await tool_func(**tool_input)
            else:
                result = tool_func(**tool_input)

            # 处理结果
            if isinstance(result, dict):
                return json.dumps(result, ensure_ascii=False, indent=2)
            else:
                return str(result)

        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return f"工具执行错误: {str(e)}"

    def get_available_tools(self) -> List[str]:
        """获取可用工具列表"""
        return list(self.tools.keys())

    def get_tool_description(self, tool_name: str) -> str:
        """获取工具描述"""
        tool = self.tools.get(tool_name)
        if tool and hasattr(tool, '__doc__'):
            return tool.__doc__ or f"工具: {tool_name}"
        return f"工具: {tool_name}"


# ============ ReAct 配置 ============

@dataclass
class ReActConfig:
    """ReAct 引擎配置"""
    max_iterations: int = 20
    timeout_seconds: int = 600
    temperature: float = 0.1

    # 模式配置
    mode: str = "security"  # security, ctf, research

    # 回调配置
    on_thought: Optional[Callable[[str, int], None]] = None
    on_action: Optional[Callable[[str, Dict, int], None]] = None
    on_observation: Optional[Callable[[str, int], None]] = None

    # 熔断器配置
    enable_circuit_breaker: bool = True
    failure_threshold: int = 3


# ============ ReAct 引擎 ============

class ReActEngine:
    """
    ReAct 思考引擎

    实现 Thought-Action-Observation 循环

    用法:
        engine = ReActEngine(
            tool_executor=executor,
            llm_caller=llm_func,
            config=ReActConfig()
        )
        result = await engine.run(task="扫描目标 192.168.1.1")
    """

    def __init__(
        self,
        tool_executor: ToolExecutor,
        llm_caller: Callable[[List[Dict[str, str]]], str],
        config: Optional[ReActConfig] = None,
        system_prompt: Optional[str] = None,
    ):
        """
        初始化 ReAct 引擎

        Args:
            tool_executor: 工具执行器
            llm_caller: LLM 调用函数
            config: 引擎配置
            system_prompt: 系统提示词
        """
        self.tool_executor = tool_executor
        self.llm_caller = llm_caller
        self.config = config or ReActConfig()
        self.system_prompt = system_prompt or self._default_system_prompt()

        # 状态
        self._cancelled = False
        self._steps: List[ReActStep] = []
        self._findings: List[Dict[str, Any]] = []
        self._flags: List[str] = []

        # 熔断器
        self._consecutive_failures = 0

    def _default_system_prompt(self) -> str:
        """生成默认系统提示词"""
        tools_desc = "\n".join([
            f"- {name}: {self.tool_executor.get_tool_description(name)}"
            for name in self.tool_executor.get_available_tools()[:20]
        ])

        return f"""你是一个专业的安全测试专家，使用 ReAct 模式进行思考和行动。

## 可用工具
{tools_desc}

## 输出格式
每次响应必须严格按照以下格式之一：

### 格式1: 继续分析
Thought: [分析当前情况，思考下一步应该做什么]
Action: [工具名称]
Action Input: {{"参数名": "参数值"}}

### 格式2: 完成任务
Thought: [总结所有发现]
Final Answer: [最终结论和发现的漏洞/Flag]

## 重要规则
1. 每次只执行一个 Action
2. 必须等待 Observation 后再决定下一步
3. Action Input 必须是有效的 JSON
4. 发现漏洞或 Flag 时立即报告
5. 不要重复执行相同的操作
"""

    async def run(
        self,
        task: str,
        context: Optional[str] = None,
        handoff: Optional[TaskHandoff] = None,
    ) -> ReActResult:
        """
        执行 ReAct 循环

        Args:
            task: 任务描述
            context: 额外上下文
            handoff: 来自上一阶段的任务交接

        Returns:
            执行结果
        """
        start_time = time.time()
        self._reset_state()

        # 构建初始消息
        messages = self._build_initial_messages(task, context, handoff)

        iteration = 0
        while iteration < self.config.max_iterations:
            # 检查取消
            if self._cancelled:
                return self._create_result(
                    success=False,
                    error="任务已取消",
                    start_time=start_time
                )

            # 检查熔断器
            if self._consecutive_failures >= self.config.failure_threshold:
                logger.warning("Circuit breaker triggered, stopping execution")
                return self._create_result(
                    success=False,
                    error="连续失败次数过多，已停止执行",
                    start_time=start_time
                )

            iteration += 1
            logger.info(f"ReAct iteration {iteration}/{self.config.max_iterations}")

            try:
                # 调用 LLM
                response = await self._call_llm(messages)

                if not response:
                    self._consecutive_failures += 1
                    messages.append({
                        "role": "user",
                        "content": "请继续分析。你的上一个响应是空的，请输出 Thought 和 Action。"
                    })
                    continue

                # 解析响应
                step = ReActParser.parse(response)
                step.iteration = iteration
                self._steps.append(step)

                # 触发回调
                await self._trigger_callbacks(step)

                # 处理步骤
                if step.step_type == StepType.FINAL_ANSWER:
                    # 检查是否有 Flag
                    self._extract_flags(step.content)
                    return self._create_result(
                        success=True,
                        final_answer=step.content,
                        start_time=start_time
                    )

                elif step.step_type == StepType.ACTION:
                    # 执行工具
                    observation = await self._execute_action(step)
                    obs_step = ReActStep(
                        step_type=StepType.OBSERVATION,
                        content=observation,
                        observation=observation,
                        iteration=iteration,
                    )
                    self._steps.append(obs_step)

                    # 检查观察结果中的 Flag
                    self._extract_flags(observation)

                    # 添加到消息历史
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": f"Observation:\n{observation}"})

                    self._consecutive_failures = 0

                elif step.step_type == StepType.THOUGHT:
                    # 只有思考，没有行动
                    messages.append({"role": "assistant", "content": response})
                    messages.append({
                        "role": "user",
                        "content": "请继续。你输出了 Thought 但没有输出 Action。请立即选择一个工具执行，或者如果任务完成，输出 Final Answer。"
                    })

                elif step.step_type == StepType.ERROR:
                    self._consecutive_failures += 1
                    messages.append({
                        "role": "user",
                        "content": f"解析错误: {step.content}\n请按照规定格式输出: Thought + Action + Action Input"
                    })

            except asyncio.TimeoutError:
                logger.error(f"Iteration {iteration} timed out")
                self._consecutive_failures += 1
                messages.append({
                    "role": "user",
                    "content": "上一步操作超时，请尝试其他方法或简化操作。"
                })

            except Exception as e:
                logger.error(f"Iteration {iteration} error: {e}")
                self._consecutive_failures += 1
                messages.append({
                    "role": "user",
                    "content": f"发生错误: {str(e)}\n请分析错误并尝试其他方法。"
                })

        # 达到最大迭代次数
        return self._create_result(
            success=False,
            error=f"达到最大迭代次数 ({self.config.max_iterations})",
            start_time=start_time
        )

    def _reset_state(self):
        """重置状态"""
        self._cancelled = False
        self._steps = []
        self._findings = []
        self._flags = []
        self._consecutive_failures = 0

    def _build_initial_messages(
        self,
        task: str,
        context: Optional[str],
        handoff: Optional[TaskHandoff]
    ) -> List[Dict[str, str]]:
        """构建初始消息列表"""
        messages = [{"role": "system", "content": self.system_prompt}]

        # 添加任务交接上下文
        if handoff:
            messages.append({
                "role": "user",
                "content": handoff.to_prompt_context()
            })

        # 添加额外上下文
        if context:
            messages.append({
                "role": "user",
                "content": f"## 背景信息\n{context}"
            })

        # 添加任务
        messages.append({
            "role": "user",
            "content": f"## 任务\n{task}\n\n请开始分析。首先思考应该做什么，然后立即选择合适的工具执行。"
        })

        return messages

    async def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        """调用 LLM"""
        try:
            if asyncio.iscoroutinefunction(self.llm_caller):
                return await self.llm_caller(messages)
            else:
                return self.llm_caller(messages)
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            raise

    async def _execute_action(self, step: ReActStep) -> str:
        """执行工具动作"""
        if not step.action:
            return "错误: 没有指定工具名称"

        tool_name = step.action
        tool_input = step.action_input or {}

        logger.info(f"Executing tool: {tool_name} with input: {tool_input}")

        start_time = time.time()
        try:
            result = await self.tool_executor.execute(tool_name, tool_input)
            duration_ms = int((time.time() - start_time) * 1000)
            step.tool_duration_ms = duration_ms

            # 截断过长的结果
            if len(result) > 4000:
                result = result[:4000] + f"\n\n... [输出已截断，共 {len(result)} 字符]"

            return result

        except asyncio.TimeoutError:
            duration_ms = int((time.time() - start_time) * 1000)
            return f"工具 '{tool_name}' 执行超时 ({duration_ms}ms)"

        except Exception as e:
            return f"工具 '{tool_name}' 执行错误: {str(e)}"

    async def _trigger_callbacks(self, step: ReActStep):
        """触发回调"""
        try:
            if step.step_type == StepType.THOUGHT and self.config.on_thought:
                if asyncio.iscoroutinefunction(self.config.on_thought):
                    await self.config.on_thought(step.content, step.iteration)
                else:
                    self.config.on_thought(step.content, step.iteration)

            elif step.step_type == StepType.ACTION and self.config.on_action:
                if asyncio.iscoroutinefunction(self.config.on_action):
                    await self.config.on_action(step.action, step.action_input, step.iteration)
                else:
                    self.config.on_action(step.action, step.action_input, step.iteration)

            elif step.step_type == StepType.OBSERVATION and self.config.on_observation:
                if asyncio.iscoroutinefunction(self.config.on_observation):
                    await self.config.on_observation(step.observation, step.iteration)
                else:
                    self.config.on_observation(step.observation, step.iteration)

        except Exception as e:
            logger.warning(f"Callback error: {e}")

    def _extract_flags(self, text: str):
        """从文本中提取 Flag"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'HCTF\{[^}]+\}',
            r'NCTF\{[^}]+\}',
        ]

        for pattern in flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self._flags:
                    self._flags.append(match)
                    logger.info(f"Flag found: {match}")

    def _create_result(
        self,
        success: bool,
        start_time: float,
        final_answer: Optional[str] = None,
        error: Optional[str] = None
    ) -> ReActResult:
        """创建执行结果"""
        total_duration = int((time.time() - start_time) * 1000)
        tool_calls = sum(1 for s in self._steps if s.step_type == StepType.ACTION)

        return ReActResult(
            success=success,
            final_answer=final_answer,
            error=error,
            iterations=len([s for s in self._steps if s.step_type in (StepType.THOUGHT, StepType.ACTION)]),
            tool_calls=tool_calls,
            total_duration_ms=total_duration,
            steps=self._steps.copy(),
            findings=self._findings.copy(),
            flags=self._flags.copy(),
        )

    def cancel(self):
        """取消执行"""
        self._cancelled = True
        logger.info("ReAct execution cancelled")


# ============ 便捷函数 ============

async def run_react(
    task: str,
    tools: Dict[str, Callable],
    llm_caller: Callable[[List[Dict[str, str]]], str],
    context: Optional[str] = None,
    max_iterations: int = 20,
) -> ReActResult:
    """
    便捷函数: 运行 ReAct 循环

    Args:
        task: 任务描述
        tools: 工具字典
        llm_caller: LLM 调用函数
        context: 额外上下文
        max_iterations: 最大迭代次数

    Returns:
        执行结果
    """
    executor = DefaultToolExecutor(tools)
    config = ReActConfig(max_iterations=max_iterations)
    engine = ReActEngine(executor, llm_caller, config)
    return await engine.run(task, context)


# ============ 导出 ============

__all__ = [
    # 类型
    "StepType",
    "ReActStep",
    "ReActResult",
    "TaskHandoff",

    # 解析器
    "ReActParser",

    # 执行器
    "ToolExecutor",
    "DefaultToolExecutor",

    # 配置和引擎
    "ReActConfig",
    "ReActEngine",

    # 便捷函数
    "run_react",
]
