#!/usr/bin/env python3
"""
Kali MCP 核心模块 v2.3

包含:
- AsyncExecutor: 异步命令执行器
- SessionManager: 会话管理
- StrategyEngine: 策略引擎
- ResultCache: 结果缓存

新增 (v2.0):
- UltimateScanEngine: 终极扫描引擎，100%工具覆盖
- ToolOrchestrator: 智能工具编排，结果驱动执行
- SmartScanOptimizer: 智能缓存和去重，避免重复扫描
- SkillDispatcher: Skill知识库集成，智能调度

新增 (v2.1) - - CircuitBreaker: 熔断器模式，防止级联失败
- RateLimiter: 速率限制器，流量控制
- ReActEngine: ReAct思考循环，智能决策
- TaskHandoff: 任务交接协议，阶段间上下文传递

新增 (v2.2) - - CTFPOCEngine: YAML POC扫描引擎，支持多步骤POC
- CTFAgentFramework: 多Agent协作架构，智能任务分发
- CTFKnowledgeBase: 知识库驱动检测，漏洞Payload模板

新增 (v2.3) - 全面优化升级:
- EnhancedKnowledgeBase: 增强知识库，300+ Payload，WAF绕过技术
- DeepAttackEngine: 深度攻击引擎，提权/横向移动/持久化
- BroadAttackOrchestrator: 广度攻击编排，125+工具链，全攻击面覆盖
- HighSpeedExecutor: 高速执行引擎，异步并发，智能调度
"""

from .executor import AsyncExecutor
from .session import SessionManager, SessionContext
from .strategy import StrategyEngine
from .cache import ResultCache

# 新增模块 v2.0
try:
    from .ultimate_engine import (
        UltimateScanEngine,
        CTFUltimateSolver,
        TargetType,
        ScanPhase,
        IterationLevel,
    )
    ULTIMATE_ENGINE_AVAILABLE = True
except ImportError:
    ULTIMATE_ENGINE_AVAILABLE = False

try:
    from .tool_orchestrator import (
        ToolOrchestrator,
        AutoPilotAttack,
        ToolCategory,
        TriggerCondition,
    )
    ORCHESTRATOR_AVAILABLE = True
except ImportError:
    ORCHESTRATOR_AVAILABLE = False

try:
    from .result_cache import (
        ScanDeduplicator,
        SmartScanOptimizer,
        IncrementalScanner,
        get_optimizer,
    )
    OPTIMIZER_AVAILABLE = True
except ImportError:
    OPTIMIZER_AVAILABLE = False

try:
    from .skill_dispatcher import (
        IntelligentDispatcher,
        SkillParser,
        TargetType,
        ScanDepth,
        ToolChain,
        get_skill_based_tools,
        get_vulnerability_tools,
        detect_target,
        skill_dispatcher,
    )
    # 为兼容性创建别名
    SkillDispatcher = IntelligentDispatcher
    SKILL_DISPATCHER_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Skill dispatcher import failed: {e}")
    SKILL_DISPATCHER_AVAILABLE = False

# 弹性模块 (v2.1) - try:
    from .resilience import (
        # 熔断器
        CircuitBreaker,
        CircuitBreakerRegistry,
        CircuitBreakerConfig,
        CircuitState,
        CircuitOpenError,
        # 速率限制器
        TokenBucketRateLimiter,
        SlidingWindowRateLimiter,
        RateLimiterRegistry,
        RateLimitExceededError,
        # 便捷函数
        get_circuit,
        get_tool_circuit,
        get_rate_limiter,
        get_resilience_status,
        # 装饰器
        with_circuit_breaker,
        rate_limited,
        # 上下文管理器
        ProtectedExecution,
    )
    RESILIENCE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Resilience module import failed: {e}")
    RESILIENCE_AVAILABLE = False

# ReAct 思考引擎 (v2.1) - try:
    from .react_engine import (
        # 核心类型
        StepType,
        ReActStep,
        ReActResult,
        # 任务交接协议
        TaskHandoff,
        # 解析器
        ReActParser,
        # 执行器
        ToolExecutor,
        DefaultToolExecutor,
        # 配置和引擎
        ReActConfig,
        ReActEngine,
    )
    REACT_ENGINE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"ReAct engine import failed: {e}")
    REACT_ENGINE_AVAILABLE = False

# 事件流系统 (v2.1) - try:
    from .event_stream import (
        # 事件类型
        EventType,
        # 数据结构
        EventData,
        StreamEvent,
        # 核心类
        EventEmitter,
        EventManager,
        # 便捷函数
        get_event_manager,
        create_emitter,
    )
    EVENT_STREAM_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Event stream import failed: {e}")
    EVENT_STREAM_AVAILABLE = False

# CTF POC扫描引擎 (v2.2) - try:
    from .ctf_poc_engine import (
        # 枚举类型
        POCSeverity,
        MatcherType,
        ExtractorType,
        # 数据结构
        POCRequest,
        POCStep,
        POCMatcher,
        POCExtractor,
        POCDefinition,
        POCResult,
        # 核心类
        HTTPClient,
        POCParser,
        POCExecutor,
        POCScanner,
        POCManager,
        # 便捷函数
        get_poc_manager,
        create_poc_from_yaml,
        quick_poc_scan,
    )
    CTF_POC_ENGINE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"CTF POC engine import failed: {e}")
    CTF_POC_ENGINE_AVAILABLE = False

# CTF 多Agent框架 (v2.2) - try:
    from .ctf_agent_framework import (
        # 枚举类型
        MessageType,
        MessagePriority,
        AgentStatus,
        # 数据结构
        AgentMessage,
        AgentContext,
        # 消息总线
        MessageBus,
        # Agent基类和实现
        BaseAgent,
        ExplorerAgent,
        ScannerAgent,
        SolutionerAgent,
        ExecutorAgent,
        # Flag检测
        FlagDetector,
        # 协调器
        CTFCoordinator,
        # 便捷函数
        create_ctf_coordinator,
        quick_ctf_solve,
    )
    CTF_AGENT_FRAMEWORK_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"CTF agent framework import failed: {e}")
    CTF_AGENT_FRAMEWORK_AVAILABLE = False

# CTF 知识库 (v2.2) - try:
    from .ctf_knowledge_base import (
        # 枚举类型
        VulnerabilityType,
        # 数据结构
        PayloadTemplate,
        DetectionMethod,
        ExploitStrategy,
        FlagGetterMethod,
        VulnerabilityKnowledge,
        # 加载器
        KnowledgeLoader,
        # 核心类
        CTFKnowledgeBase,
        KnowledgeDrivenDetector,
        # 便捷函数
        get_knowledge_base,
        get_payloads,
        get_flag_getters,
        detect_flags,
        suggest_action,
    )
    CTF_KNOWLEDGE_BASE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"CTF knowledge base import failed: {e}")
    CTF_KNOWLEDGE_BASE_AVAILABLE = False

# ==================== v2.3 新增模块 ====================

# 增强知识库 (v2.3)
try:
    from .enhanced_knowledge_base import (
        # 枚举类型
        ExtendedVulnerabilityType,
        # Payload集合
        SQL_INJECTION_PAYLOADS,
        XSS_PAYLOADS,
        COMMAND_INJECTION_PAYLOADS,
        LFI_PAYLOADS,
        SSTI_PAYLOADS,
        SSRF_PAYLOADS,
        XXE_PAYLOADS,
        JWT_PAYLOADS,
        DESERIALIZATION_PAYLOADS,
        # 攻击链
        ATTACK_CHAINS,
        # 核心类
        EnhancedDetector,
    )
    ENHANCED_KNOWLEDGE_BASE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Enhanced knowledge base import failed: {e}")
    ENHANCED_KNOWLEDGE_BASE_AVAILABLE = False

# 深度攻击引擎 (v2.3)
try:
    from .deep_attack_engine import (
        # 枚举类型
        AttackPhase,
        TargetOS,
        ExploitDifficulty,
        # 数据结构
        ExploitTechnique,
        PrivilegeEscalation,
        LateralMoveTechnique,
        PersistenceTechnique,
        AttackChainResult,
        # 技术集合
        LINUX_PRIVESC_TECHNIQUES,
        WINDOWS_PRIVESC_TECHNIQUES,
        LATERAL_MOVEMENT_TECHNIQUES,
        PERSISTENCE_TECHNIQUES,
        # 核心类
        DeepAttackEngine,
    )
    DEEP_ATTACK_ENGINE_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Deep attack engine import failed: {e}")
    DEEP_ATTACK_ENGINE_AVAILABLE = False

# 广度攻击编排器 (v2.3)
try:
    from .broad_attack_orchestrator import (
        # 枚举类型
        AttackSurface,
        ServiceType,
        # 数据结构
        ToolChain as BroadToolChain,
        AttackVector,
        # 工具链集合
        WEB_TOOL_CHAINS,
        NETWORK_TOOL_CHAINS,
        DATABASE_TOOL_CHAINS,
        AD_TOOL_CHAINS,
        CLOUD_TOOL_CHAINS,
        # 映射
        SERVICE_PORT_MAP,
        # 核心类
        BroadAttackOrchestrator,
        # 便捷函数
        get_orchestrator,
        get_chains_for_port,
        suggest_tools_for_target,
        get_attack_surface_stats,
    )
    BROAD_ATTACK_ORCHESTRATOR_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Broad attack orchestrator import failed: {e}")
    BROAD_ATTACK_ORCHESTRATOR_AVAILABLE = False

# 高速执行引擎 (v2.3)
try:
    from .high_speed_executor import (
        # 枚举类型
        TaskPriority,
        TaskStatus,
        # 数据结构
        Task,
        ExecutionStats,
        # 核心类
        LRUCache,
        AdaptiveRateLimiter,
        TaskScheduler,
        HighSpeedExecutor,
        # 工厂
        FastExecutorFactory,
        # 预设
        FAST_SCAN_PRESETS,
        # 便捷函数
        get_executor,
        quick_execute,
        quick_execute_async,
        parallel_execute,
        parallel_execute_async,
        get_execution_stats,
    )
    HIGH_SPEED_EXECUTOR_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"High speed executor import failed: {e}")
    HIGH_SPEED_EXECUTOR_AVAILABLE = False

__all__ = [
    # 原有模块
    "AsyncExecutor",
    "SessionManager",
    "SessionContext",
    "StrategyEngine",
    "ResultCache",

    # 终极扫描引擎 (v2.0)
    "UltimateScanEngine",
    "CTFUltimateSolver",
    "TargetType",
    "ScanPhase",
    "IterationLevel",

    # 智能编排 (v2.0)
    "ToolOrchestrator",
    "AutoPilotAttack",
    "ToolCategory",
    "TriggerCondition",

    # 缓存和去重 (v2.0)
    "ScanDeduplicator",
    "SmartScanOptimizer",
    "IncrementalScanner",
    "get_optimizer",

    # Skill调度 (v2.0)
    "SkillDispatcher",
    "IntelligentDispatcher",
    "SkillParser",
    "get_skill_based_tools",
    "get_vulnerability_tools",
    "detect_target",
    "skill_dispatcher",

    # 弹性模块 (v2.1)
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitBreakerConfig",
    "CircuitState",
    "CircuitOpenError",
    "TokenBucketRateLimiter",
    "SlidingWindowRateLimiter",
    "RateLimiterRegistry",
    "RateLimitExceededError",
    "get_circuit",
    "get_tool_circuit",
    "get_rate_limiter",
    "get_resilience_status",
    "with_circuit_breaker",
    "rate_limited",
    "ProtectedExecution",

    # ReAct 思考引擎 (v2.1)
    "StepType",
    "ReActStep",
    "ReActResult",
    "TaskHandoff",
    "ReActParser",
    "ToolExecutor",
    "DefaultToolExecutor",
    "ReActConfig",
    "ReActEngine",

    # 事件流系统 (v2.1)
    "EventType",
    "EventData",
    "StreamEvent",
    "EventEmitter",
    "EventManager",
    "get_event_manager",
    "create_emitter",

    # CTF POC扫描引擎 (v2.2)
    "POCSeverity",
    "MatcherType",
    "ExtractorType",
    "POCRequest",
    "POCStep",
    "POCMatcher",
    "POCExtractor",
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

    # CTF 多Agent框架 (v2.2)
    "MessageType",
    "MessagePriority",
    "AgentStatus",
    "AgentMessage",
    "AgentContext",
    "MessageBus",
    "BaseAgent",
    "ExplorerAgent",
    "ScannerAgent",
    "SolutionerAgent",
    "ExecutorAgent",
    "FlagDetector",
    "CTFCoordinator",
    "create_ctf_coordinator",
    "quick_ctf_solve",

    # CTF 知识库 (v2.2)
    "VulnerabilityType",
    "PayloadTemplate",
    "DetectionMethod",
    "ExploitStrategy",
    "FlagGetterMethod",
    "VulnerabilityKnowledge",
    "KnowledgeLoader",
    "CTFKnowledgeBase",
    "KnowledgeDrivenDetector",
    "get_knowledge_base",
    "get_payloads",
    "get_flag_getters",
    "detect_flags",
    "suggest_action",

    # ==================== v2.3 新增 ====================

    # 增强知识库 (v2.3)
    "ExtendedVulnerabilityType",
    "SQL_INJECTION_PAYLOADS",
    "XSS_PAYLOADS",
    "COMMAND_INJECTION_PAYLOADS",
    "LFI_PAYLOADS",
    "SSTI_PAYLOADS",
    "SSRF_PAYLOADS",
    "XXE_PAYLOADS",
    "JWT_PAYLOADS",
    "DESERIALIZATION_PAYLOADS",
    "ATTACK_CHAINS",
    "EnhancedDetector",

    # 深度攻击引擎 (v2.3)
    "AttackPhase",
    "TargetOS",
    "ExploitDifficulty",
    "ExploitTechnique",
    "PrivilegeEscalation",
    "LateralMoveTechnique",
    "PersistenceTechnique",
    "AttackChainResult",
    "LINUX_PRIVESC_TECHNIQUES",
    "WINDOWS_PRIVESC_TECHNIQUES",
    "LATERAL_MOVEMENT_TECHNIQUES",
    "PERSISTENCE_TECHNIQUES",
    "DeepAttackEngine",

    # 广度攻击编排器 (v2.3)
    "AttackSurface",
    "ServiceType",
    "BroadToolChain",
    "AttackVector",
    "WEB_TOOL_CHAINS",
    "NETWORK_TOOL_CHAINS",
    "DATABASE_TOOL_CHAINS",
    "AD_TOOL_CHAINS",
    "CLOUD_TOOL_CHAINS",
    "SERVICE_PORT_MAP",
    "BroadAttackOrchestrator",
    "get_orchestrator",
    "get_chains_for_port",
    "suggest_tools_for_target",
    "get_attack_surface_stats",

    # 高速执行引擎 (v2.3)
    "TaskPriority",
    "TaskStatus",
    "Task",
    "ExecutionStats",
    "LRUCache",
    "AdaptiveRateLimiter",
    "TaskScheduler",
    "HighSpeedExecutor",
    "FastExecutorFactory",
    "FAST_SCAN_PRESETS",
    "get_executor",
    "quick_execute",
    "quick_execute_async",
    "parallel_execute",
    "parallel_execute_async",
    "get_execution_stats",

    # 可用性标志
    "ULTIMATE_ENGINE_AVAILABLE",
    "ORCHESTRATOR_AVAILABLE",
    "OPTIMIZER_AVAILABLE",
    "SKILL_DISPATCHER_AVAILABLE",
    "RESILIENCE_AVAILABLE",
    "REACT_ENGINE_AVAILABLE",
    "EVENT_STREAM_AVAILABLE",
    "CTF_POC_ENGINE_AVAILABLE",
    "CTF_AGENT_FRAMEWORK_AVAILABLE",
    "CTF_KNOWLEDGE_BASE_AVAILABLE",
    "ENHANCED_KNOWLEDGE_BASE_AVAILABLE",
    "DEEP_ATTACK_ENGINE_AVAILABLE",
    "BROAD_ATTACK_ORCHESTRATOR_AVAILABLE",
    "HIGH_SPEED_EXECUTOR_AVAILABLE",
]

# 版本信息
__version__ = "2.3.0"
__description__ = "Kali MCP 核心模块 - 智能化安全测试系统 (全面优化升级版)"
