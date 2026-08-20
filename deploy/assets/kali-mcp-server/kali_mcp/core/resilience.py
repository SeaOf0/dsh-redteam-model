#!/usr/bin/env python3
"""
Kali MCP 弹性模块 v2.0

关键架构组件:
- CircuitBreaker: 熔断器模式，防止级联故障
- RateLimiter: 速率限制器，防止资源耗尽
- RetryPolicy: 智能重试策略

适配场景:
- 安全工具执行的容错处理
- 外部API调用的流量控制
- 并发扫描的资源保护
"""

import asyncio
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, List, Optional, TypeVar, Union
import threading

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============ 自定义异常 ============

class CircuitOpenError(Exception):
    """熔断器开启时抛出的异常"""
    def __init__(self, circuit_name: str, recovery_time: float = 0):
        self.circuit_name = circuit_name
        self.recovery_time = recovery_time
        super().__init__(f"Circuit '{circuit_name}' is OPEN. Recovery in {recovery_time:.1f}s")


class RateLimitExceededError(Exception):
    """速率限制超出时抛出的异常"""
    def __init__(self, limiter_name: str, wait_time: float = 0):
        self.limiter_name = limiter_name
        self.wait_time = wait_time
        super().__init__(f"Rate limit exceeded for '{limiter_name}'. Wait {wait_time:.1f}s")


# ============ 熔断器状态 ============

class CircuitState(str, Enum):
    """熔断器状态"""
    CLOSED = "closed"      # 正常状态，允许调用
    OPEN = "open"          # 熔断状态，拒绝调用
    HALF_OPEN = "half_open"  # 半开状态，允许探测性调用


# ============ 熔断器配置 ============

@dataclass
class CircuitBreakerConfig:
    """熔断器配置"""
    failure_threshold: int = 5       # 连续失败次数阈值
    success_threshold: int = 3       # 半开状态成功次数阈值
    recovery_timeout: float = 30.0   # 熔断恢复超时(秒)
    half_open_max_calls: int = 3     # 半开状态最大探测调用数
    excluded_exceptions: tuple = ()   # 不触发熔断的异常类型

    # Kali MCP 特定配置
    tool_category: str = "general"   # 工具类别
    auto_reset_on_success: bool = True  # 成功后自动重置


# 预定义的工具类别配置
TOOL_CIRCUIT_CONFIGS = {
    "network_scan": CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=60.0,
        tool_category="network_scan"
    ),
    "web_scan": CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=30.0,
        tool_category="web_scan"
    ),
    "exploit": CircuitBreakerConfig(
        failure_threshold=2,
        recovery_timeout=120.0,  # exploit失败后等待更长时间
        tool_category="exploit"
    ),
    "bruteforce": CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=90.0,
        tool_category="bruteforce"
    ),
    "external_api": CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=30.0,
        tool_category="external_api"
    ),
}


# ============ 熔断器统计 ============

@dataclass
class CircuitStats:
    """熔断器统计信息"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    last_error: Optional[str] = None

    @property
    def failure_rate(self) -> float:
        """计算失败率"""
        return self.failed_calls / self.total_calls if self.total_calls > 0 else 0.0

    @property
    def success_rate(self) -> float:
        """计算成功率"""
        return self.successful_calls / self.total_calls if self.total_calls > 0 else 1.0

    def record_success(self):
        """记录成功调用"""
        self.total_calls += 1
        self.successful_calls += 1
        self.consecutive_successes += 1
        self.consecutive_failures = 0
        self.last_success_time = time.time()

    def record_failure(self, error: Optional[str] = None):
        """记录失败调用"""
        self.total_calls += 1
        self.failed_calls += 1
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.last_failure_time = time.time()
        self.last_error = error

    def record_rejection(self):
        """记录被拒绝的调用"""
        self.rejected_calls += 1

    def reset(self):
        """重置统计"""
        self.consecutive_failures = 0
        self.consecutive_successes = 0

    def full_reset(self):
        """完全重置"""
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.rejected_calls = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_error = None


# ============ 熔断器实现 ============

class CircuitBreaker:
    """
    熔断器实现

    用法:
        # 方式1: 直接调用
        circuit = CircuitBreaker("nmap_scan")
        result = await circuit.call(lambda: execute_nmap(target))

        # 方式2: 装饰器
        @circuit.protect
        async def my_scan():
            ...

        # 方式3: 上下文管理器
        async with circuit:
            result = await execute_scan()
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()
        self._half_open_calls = 0
        self._last_state_change = time.time()
        self._state_change_callbacks: List[Callable] = []

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def stats(self) -> CircuitStats:
        return self._stats

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    @property
    def time_in_current_state(self) -> float:
        return time.time() - self._last_state_change

    @property
    def time_until_recovery(self) -> float:
        """返回距离恢复的剩余时间"""
        if self._state != CircuitState.OPEN:
            return 0
        elapsed = time.time() - self._last_state_change
        remaining = self.config.recovery_timeout - elapsed
        return max(0, remaining)

    def add_state_change_callback(self, callback: Callable[[str, CircuitState, CircuitState], None]):
        """添加状态变化回调"""
        self._state_change_callbacks.append(callback)

    async def _transition_to(self, new_state: CircuitState) -> None:
        """状态转换"""
        if self._state == new_state:
            return

        old_state = self._state
        self._state = new_state
        self._last_state_change = time.time()

        if new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
        elif new_state == CircuitState.CLOSED:
            self._stats.reset()

        # 记录状态变化
        logger.info(f"Circuit '{self.name}' state: {old_state.value} -> {new_state.value}")

        # 触发回调
        for callback in self._state_change_callbacks:
            try:
                callback(self.name, old_state, new_state)
            except Exception as e:
                logger.warning(f"State change callback error: {e}")

    def _sync_transition_to(self, new_state: CircuitState) -> None:
        """同步版本的状态转换"""
        if self._state == new_state:
            return

        old_state = self._state
        self._state = new_state
        self._last_state_change = time.time()

        if new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
        elif new_state == CircuitState.CLOSED:
            self._stats.reset()

        logger.info(f"Circuit '{self.name}' state: {old_state.value} -> {new_state.value}")

    async def _check_state(self) -> bool:
        """检查是否允许调用"""
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True

            elif self._state == CircuitState.OPEN:
                # 检查是否可以进入半开状态
                if time.time() - self._last_state_change >= self.config.recovery_timeout:
                    await self._transition_to(CircuitState.HALF_OPEN)
                    return True
                self._stats.record_rejection()
                return False

            elif self._state == CircuitState.HALF_OPEN:
                # 限制半开状态的调用数
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                self._stats.record_rejection()
                return False

        return False

    def _sync_check_state(self) -> bool:
        """同步版本的状态检查"""
        with self._sync_lock:
            if self._state == CircuitState.CLOSED:
                return True

            elif self._state == CircuitState.OPEN:
                if time.time() - self._last_state_change >= self.config.recovery_timeout:
                    self._sync_transition_to(CircuitState.HALF_OPEN)
                    return True
                self._stats.record_rejection()
                return False

            elif self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                self._stats.record_rejection()
                return False

        return False

    async def _on_success(self) -> None:
        """处理成功调用"""
        async with self._lock:
            self._stats.record_success()

            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.config.success_threshold:
                    await self._transition_to(CircuitState.CLOSED)

    def _sync_on_success(self) -> None:
        """同步版本的成功处理"""
        with self._sync_lock:
            self._stats.record_success()

            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.config.success_threshold:
                    self._sync_transition_to(CircuitState.CLOSED)

    async def _on_failure(self, error: Exception) -> None:
        """处理失败调用"""
        # 检查是否是排除的异常类型
        if isinstance(error, self.config.excluded_exceptions):
            return

        async with self._lock:
            self._stats.record_failure(str(error))

            if self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)

            elif self._state == CircuitState.HALF_OPEN:
                # 半开状态下任何失败都回到开启状态
                await self._transition_to(CircuitState.OPEN)

    def _sync_on_failure(self, error: Exception) -> None:
        """同步版本的失败处理"""
        if isinstance(error, self.config.excluded_exceptions):
            return

        with self._sync_lock:
            self._stats.record_failure(str(error))

            if self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    self._sync_transition_to(CircuitState.OPEN)

            elif self._state == CircuitState.HALF_OPEN:
                self._sync_transition_to(CircuitState.OPEN)

    async def call(self, func: Callable[[], Awaitable[T]]) -> T:
        """执行受保护的异步调用"""
        if not await self._check_state():
            raise CircuitOpenError(self.name, self.time_until_recovery)

        try:
            result = await func()
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure(e)
            raise

    def sync_call(self, func: Callable[[], T]) -> T:
        """执行受保护的同步调用"""
        if not self._sync_check_state():
            raise CircuitOpenError(self.name, self.time_until_recovery)

        try:
            result = func()
            self._sync_on_success()
            return result
        except Exception as e:
            self._sync_on_failure(e)
            raise

    async def __aenter__(self) -> "CircuitBreaker":
        if not await self._check_state():
            raise CircuitOpenError(self.name, self.time_until_recovery)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_val is not None:
            await self._on_failure(exc_val)
        else:
            await self._on_success()
        return False

    def __enter__(self) -> "CircuitBreaker":
        if not self._sync_check_state():
            raise CircuitOpenError(self.name, self.time_until_recovery)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_val is not None:
            self._sync_on_failure(exc_val)
        else:
            self._sync_on_success()
        return False

    def protect(self, func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        """装饰器: 保护异步函数"""
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await self.call(lambda: func(*args, **kwargs))
        return wrapper

    def protect_sync(self, func: Callable[..., T]) -> Callable[..., T]:
        """装饰器: 保护同步函数"""
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.sync_call(lambda: func(*args, **kwargs))
        return wrapper

    async def reset(self) -> None:
        """重置熔断器"""
        async with self._lock:
            await self._transition_to(CircuitState.CLOSED)
            self._stats.full_reset()

    def sync_reset(self) -> None:
        """同步重置熔断器"""
        with self._sync_lock:
            self._sync_transition_to(CircuitState.CLOSED)
            self._stats.full_reset()

    def get_status(self) -> Dict[str, Any]:
        """获取熔断器状态"""
        return {
            "name": self.name,
            "state": self._state.value,
            "tool_category": self.config.tool_category,
            "stats": {
                "total_calls": self._stats.total_calls,
                "successful_calls": self._stats.successful_calls,
                "failed_calls": self._stats.failed_calls,
                "rejected_calls": self._stats.rejected_calls,
                "success_rate": f"{self._stats.success_rate:.1%}",
                "failure_rate": f"{self._stats.failure_rate:.1%}",
                "consecutive_failures": self._stats.consecutive_failures,
                "last_error": self._stats.last_error,
            },
            "time_in_state": f"{self.time_in_current_state:.1f}s",
            "time_until_recovery": f"{self.time_until_recovery:.1f}s" if self.is_open else "N/A",
        }


# ============ 熔断器注册表 ============

class CircuitBreakerRegistry:
    """熔断器注册表，管理所有熔断器实例"""

    _instance: Optional["CircuitBreakerRegistry"] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._circuits: Dict[str, CircuitBreaker] = {}
                    cls._instance._default_config = CircuitBreakerConfig()
        return cls._instance

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """获取或创建熔断器"""
        if name not in self._circuits:
            self._circuits[name] = CircuitBreaker(name, config or self._default_config)
        return self._circuits[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """获取熔断器"""
        return self._circuits.get(name)

    def get_by_category(self, category: str) -> List[CircuitBreaker]:
        """按类别获取熔断器"""
        return [
            cb for cb in self._circuits.values()
            if cb.config.tool_category == category
        ]

    async def reset_all(self) -> None:
        """重置所有熔断器"""
        for circuit in self._circuits.values():
            await circuit.reset()

    def sync_reset_all(self) -> None:
        """同步重置所有熔断器"""
        for circuit in self._circuits.values():
            circuit.sync_reset()

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有熔断器状态"""
        return {name: circuit.get_status() for name, circuit in self._circuits.items()}

    def get_open_circuits(self) -> List[str]:
        """获取所有处于开启状态的熔断器"""
        return [name for name, cb in self._circuits.items() if cb.is_open]

    def get_summary(self) -> Dict[str, Any]:
        """获取汇总信息"""
        total = len(self._circuits)
        open_count = sum(1 for cb in self._circuits.values() if cb.is_open)
        half_open_count = sum(1 for cb in self._circuits.values() if cb.is_half_open)
        closed_count = total - open_count - half_open_count

        return {
            "total_circuits": total,
            "closed": closed_count,
            "open": open_count,
            "half_open": half_open_count,
            "open_circuits": self.get_open_circuits(),
        }


# ============ 速率限制器 ============

class TokenBucketRateLimiter:
    """
    令牌桶速率限制器

    允许突发流量达到 burst 个令牌，然后限制为每秒 rate 个令牌

    用法:
        limiter = TokenBucketRateLimiter(rate=1.0, burst=5)
        await limiter.acquire()  # 等待获取令牌
        # 执行受限操作
    """

    def __init__(self, rate: float, burst: int, name: str = "default"):
        """
        初始化速率限制器

        Args:
            rate: 每秒补充的令牌数
            burst: 桶的最大容量
            name: 限制器名称
        """
        self.rate = rate
        self.burst = burst
        self.name = name
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

    def _replenish(self) -> None:
        """补充令牌"""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now

    async def acquire(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """
        获取令牌，如果需要则等待

        Args:
            tokens: 需要获取的令牌数
            timeout: 最大等待时间

        Returns:
            True 如果成功获取，False 如果超时
        """
        start_time = time.monotonic()

        while True:
            async with self._lock:
                self._replenish()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate

            # 检查超时
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed + wait_time > timeout:
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            await asyncio.sleep(wait_time)

    def sync_acquire(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """同步版本的获取令牌"""
        start_time = time.monotonic()

        while True:
            with self._sync_lock:
                self._replenish()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate

            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed + wait_time > timeout:
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            time.sleep(wait_time)

    async def try_acquire(self, tokens: int = 1) -> bool:
        """尝试获取令牌，不等待"""
        async with self._lock:
            self._replenish()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def sync_try_acquire(self, tokens: int = 1) -> bool:
        """同步版本的尝试获取"""
        with self._sync_lock:
            self._replenish()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    @property
    def available_tokens(self) -> float:
        """获取当前可用令牌数（近似值）"""
        elapsed = time.monotonic() - self.last_update
        return min(self.burst, self.tokens + elapsed * self.rate)

    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        return {
            "name": self.name,
            "rate": f"{self.rate}/s",
            "burst": self.burst,
            "available_tokens": f"{self.available_tokens:.1f}",
        }


# ============ 滑动窗口限制器 ============

class SlidingWindowRateLimiter:
    """
    滑动窗口速率限制器

    在 window_seconds 秒内最多允许 max_requests 个请求
    """

    def __init__(self, max_requests: int, window_seconds: float, name: str = "default"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name
        self.requests: List[float] = []
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """获取许可"""
        start_time = time.monotonic()

        while True:
            async with self._lock:
                now = time.monotonic()
                # 移除过期的请求记录
                self.requests = [t for t in self.requests if now - t < self.window_seconds]

                if len(self.requests) < self.max_requests:
                    self.requests.append(now)
                    return True

                # 计算等待时间
                oldest = min(self.requests)
                wait_time = self.window_seconds - (now - oldest)

            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed + wait_time > timeout:
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            await asyncio.sleep(wait_time + 0.01)

    async def try_acquire(self) -> bool:
        """尝试获取，不等待"""
        async with self._lock:
            now = time.monotonic()
            self.requests = [t for t in self.requests if now - t < self.window_seconds]

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        now = time.monotonic()
        active_requests = len([t for t in self.requests if now - t < self.window_seconds])
        return {
            "name": self.name,
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "current_requests": active_requests,
            "available": self.max_requests - active_requests,
        }


# ============ 速率限制器注册表 ============

class RateLimiterRegistry:
    """速率限制器注册表"""

    _instance: Optional["RateLimiterRegistry"] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._limiters: Dict[str, TokenBucketRateLimiter] = {}
        return cls._instance

    def get_or_create(
        self,
        name: str,
        rate: float = 1.0,
        burst: int = 5
    ) -> TokenBucketRateLimiter:
        """获取或创建限制器"""
        if name not in self._limiters:
            self._limiters[name] = TokenBucketRateLimiter(rate, burst, name)
        return self._limiters[name]

    def get(self, name: str) -> Optional[TokenBucketRateLimiter]:
        """获取限制器"""
        return self._limiters.get(name)

    def get_all_status(self) -> Dict[str, Dict]:
        """获取所有限制器状态"""
        return {name: limiter.get_status() for name, limiter in self._limiters.items()}


# ============ 便捷函数 ============

def get_circuit_registry() -> CircuitBreakerRegistry:
    """获取全局熔断器注册表"""
    return CircuitBreakerRegistry()


def get_circuit(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """获取或创建熔断器"""
    return get_circuit_registry().get_or_create(name, config)


def get_tool_circuit(tool_name: str, category: str = "general") -> CircuitBreaker:
    """获取工具专用熔断器"""
    config = TOOL_CIRCUIT_CONFIGS.get(category, CircuitBreakerConfig(tool_category=category))
    return get_circuit(f"tool_{tool_name}", config)


def get_rate_limiter_registry() -> RateLimiterRegistry:
    """获取全局速率限制器注册表"""
    return RateLimiterRegistry()


def get_rate_limiter(name: str, rate: float = 1.0, burst: int = 5) -> TokenBucketRateLimiter:
    """获取或创建速率限制器"""
    return get_rate_limiter_registry().get_or_create(name, rate, burst)


# ============ 预定义的速率限制器 ============

def get_scan_rate_limiter() -> TokenBucketRateLimiter:
    """扫描工具速率限制器 (2/秒, 突发10)"""
    return get_rate_limiter("scan_tools", rate=2.0, burst=10)


def get_exploit_rate_limiter() -> TokenBucketRateLimiter:
    """漏洞利用速率限制器 (0.5/秒, 突发3)"""
    return get_rate_limiter("exploit_tools", rate=0.5, burst=3)


def get_bruteforce_rate_limiter() -> TokenBucketRateLimiter:
    """暴力破解速率限制器 (0.2/秒, 突发2)"""
    return get_rate_limiter("bruteforce_tools", rate=0.2, burst=2)


def get_api_rate_limiter() -> TokenBucketRateLimiter:
    """外部API速率限制器 (1/秒, 突发5)"""
    return get_rate_limiter("external_api", rate=1.0, burst=5)


# ============ 装饰器 ============

def with_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """熔断器装饰器"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        circuit = get_circuit(name, config)

        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await circuit.call(lambda: func(*args, **kwargs))

        return wrapper
    return decorator


def with_circuit_breaker_sync(name: str, config: Optional[CircuitBreakerConfig] = None):
    """同步熔断器装饰器"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        circuit = get_circuit(name, config)

        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return circuit.sync_call(lambda: func(*args, **kwargs))

        return wrapper
    return decorator


def rate_limited(name: str, rate: float = 1.0, burst: int = 5):
    """速率限制装饰器"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            limiter = get_rate_limiter(name, rate, burst)
            await limiter.acquire()
            return await func(*args, **kwargs)

        return wrapper
    return decorator


def rate_limited_sync(name: str, rate: float = 1.0, burst: int = 5):
    """同步速率限制装饰器"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            limiter = get_rate_limiter(name, rate, burst)
            limiter.sync_acquire()
            return func(*args, **kwargs)

        return wrapper
    return decorator


# ============ 上下文管理器 ============

class ProtectedExecution:
    """
    受保护的执行上下文

    结合熔断器和速率限制器

    用法:
        async with ProtectedExecution("nmap", category="network_scan"):
            result = await execute_nmap(target)
    """

    def __init__(
        self,
        name: str,
        category: str = "general",
        rate_limit: Optional[float] = None,
        burst: int = 5
    ):
        self.name = name
        self.circuit = get_tool_circuit(name, category)
        self.rate_limiter = get_rate_limiter(f"{name}_rate", rate_limit or 1.0, burst) if rate_limit else None

    async def __aenter__(self):
        # 先检查速率限制
        if self.rate_limiter:
            acquired = await self.rate_limiter.try_acquire()
            if not acquired:
                raise RateLimitExceededError(self.name)

        # 再检查熔断器
        if not await self.circuit._check_state():
            raise CircuitOpenError(self.name, self.circuit.time_until_recovery)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            await self.circuit._on_failure(exc_val)
        else:
            await self.circuit._on_success()
        return False


# ============ 获取综合状态 ============

def get_resilience_status() -> Dict[str, Any]:
    """获取弹性模块综合状态"""
    circuit_registry = get_circuit_registry()
    rate_registry = get_rate_limiter_registry()

    return {
        "circuit_breakers": circuit_registry.get_summary(),
        "rate_limiters": rate_registry.get_all_status(),
        "circuit_details": circuit_registry.get_all_status(),
    }


# ============ 导出 ============

__all__ = [
    # 异常
    "CircuitOpenError",
    "RateLimitExceededError",

    # 枚举
    "CircuitState",

    # 配置
    "CircuitBreakerConfig",
    "TOOL_CIRCUIT_CONFIGS",

    # 熔断器
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitStats",

    # 速率限制器
    "TokenBucketRateLimiter",
    "SlidingWindowRateLimiter",
    "RateLimiterRegistry",

    # 便捷函数
    "get_circuit_registry",
    "get_circuit",
    "get_tool_circuit",
    "get_rate_limiter_registry",
    "get_rate_limiter",
    "get_scan_rate_limiter",
    "get_exploit_rate_limiter",
    "get_bruteforce_rate_limiter",
    "get_api_rate_limiter",

    # 装饰器
    "with_circuit_breaker",
    "with_circuit_breaker_sync",
    "rate_limited",
    "rate_limited_sync",

    # 上下文管理器
    "ProtectedExecution",

    # 状态
    "get_resilience_status",
]
