#!/usr/bin/env python3
"""
异步命令执行器

提供高性能的异步命令执行能力:
- 异步subprocess执行
- 并行任务处理
- 超时控制
- 实时输出流
"""

import asyncio
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """执行状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """命令执行结果"""
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    execution_time: float = 0.0
    status: ExecutionStatus = ExecutionStatus.COMPLETED
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "execution_time": self.execution_time,
            "status": self.status.value,
            "error_message": self.error_message
        }


@dataclass
class TaskInfo:
    """任务信息"""
    task_id: str
    command: str
    status: ExecutionStatus = ExecutionStatus.PENDING
    result: Optional[ExecutionResult] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    progress_callback: Optional[Callable] = None


class AsyncExecutor:
    """异步命令执行器 - 支持并行执行和实时进度"""

    def __init__(
        self,
        max_concurrent: int = 10,
        default_timeout: int = 300,
        shell: str = "/bin/bash"
    ):
        """
        初始化异步执行器

        Args:
            max_concurrent: 最大并发任务数
            default_timeout: 默认超时时间(秒)
            shell: 使用的shell
        """
        self.max_concurrent = max_concurrent
        self.default_timeout = default_timeout
        self.shell = shell

        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: Dict[str, TaskInfo] = {}
        self._lock = asyncio.Lock()

        # 统计信息
        self.stats = {
            "total_executed": 0,
            "successful": 0,
            "failed": 0,
            "timeout": 0,
            "total_execution_time": 0.0
        }

        logger.info(f"AsyncExecutor初始化: max_concurrent={max_concurrent}, timeout={default_timeout}")

    def _generate_task_id(self, command: str) -> str:
        """生成任务ID"""
        timestamp = str(time.time())
        hash_input = f"{command}:{timestamp}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]

    async def run_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        progress_callback: Optional[Callable] = None
    ) -> ExecutionResult:
        """
        异步执行单个命令

        Args:
            command: 要执行的命令
            timeout: 超时时间(秒)
            cwd: 工作目录
            env: 环境变量
            progress_callback: 进度回调函数

        Returns:
            ExecutionResult对象
        """
        timeout = timeout or self.default_timeout
        task_id = self._generate_task_id(command)

        task_info = TaskInfo(
            task_id=task_id,
            command=command,
            progress_callback=progress_callback
        )

        async with self._lock:
            self._tasks[task_id] = task_info

        start_time = time.time()
        task_info.start_time = start_time
        task_info.status = ExecutionStatus.RUNNING

        try:
            async with self._semaphore:
                # 创建子进程
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=env
                )

                try:
                    # 等待完成或超时
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout
                    )

                    execution_time = time.time() - start_time
                    success = process.returncode == 0

                    result = ExecutionResult(
                        success=success,
                        stdout=stdout.decode('utf-8', errors='replace'),
                        stderr=stderr.decode('utf-8', errors='replace'),
                        return_code=process.returncode,
                        execution_time=execution_time,
                        status=ExecutionStatus.COMPLETED
                    )

                    # 更新统计
                    self.stats["total_executed"] += 1
                    self.stats["total_execution_time"] += execution_time
                    if success:
                        self.stats["successful"] += 1
                    else:
                        self.stats["failed"] += 1

                    logger.debug(f"命令完成: {command[:50]}... (耗时: {execution_time:.2f}s)")

                except asyncio.TimeoutError:
                    # 超时处理
                    process.kill()
                    await process.wait()

                    execution_time = time.time() - start_time
                    result = ExecutionResult(
                        success=False,
                        execution_time=execution_time,
                        status=ExecutionStatus.TIMEOUT,
                        error_message=f"命令执行超时 ({timeout}秒)"
                    )

                    self.stats["total_executed"] += 1
                    self.stats["timeout"] += 1

                    logger.warning(f"命令超时: {command[:50]}...")

        except Exception as e:
            execution_time = time.time() - start_time
            result = ExecutionResult(
                success=False,
                execution_time=execution_time,
                status=ExecutionStatus.FAILED,
                error_message=str(e)
            )

            self.stats["total_executed"] += 1
            self.stats["failed"] += 1

            logger.error(f"命令执行错误: {e}")

        finally:
            task_info.end_time = time.time()
            task_info.status = result.status
            task_info.result = result

        return result

    async def run_parallel(
        self,
        commands: List[str],
        timeout: Optional[int] = None,
        fail_fast: bool = False
    ) -> List[ExecutionResult]:
        """
        并行执行多个命令

        Args:
            commands: 命令列表
            timeout: 单个命令的超时时间
            fail_fast: 是否在第一个失败时停止

        Returns:
            ExecutionResult列表
        """
        if not commands:
            return []

        logger.info(f"并行执行 {len(commands)} 个命令...")

        tasks = [
            asyncio.ensure_future(self.run_command(cmd, timeout=timeout))
            for cmd in commands
        ]

        if fail_fast:
            results = []
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                if not result.success:
                    # 取消剩余任务
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    break
            return results
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 处理异常结果
            processed_results = []
            for r in results:
                if isinstance(r, Exception):
                    processed_results.append(ExecutionResult(
                        success=False,
                        status=ExecutionStatus.FAILED,
                        error_message=str(r)
                    ))
                else:
                    processed_results.append(r)

            return processed_results

    async def run_pipeline(
        self,
        commands: List[str],
        timeout: Optional[int] = None,
        stop_on_failure: bool = True
    ) -> List[ExecutionResult]:
        """
        顺序执行命令管道

        Args:
            commands: 命令列表
            timeout: 单个命令的超时时间
            stop_on_failure: 失败时是否停止

        Returns:
            ExecutionResult列表
        """
        results = []

        for cmd in commands:
            result = await self.run_command(cmd, timeout=timeout)
            results.append(result)

            if stop_on_failure and not result.success:
                logger.warning(f"管道在命令失败时停止: {cmd[:50]}...")
                break

        return results

    def get_stats(self) -> Dict[str, Any]:
        """获取执行统计信息"""
        total = self.stats["total_executed"]
        return {
            **self.stats,
            "success_rate": f"{(self.stats['successful'] / max(1, total)) * 100:.1f}%",
            "avg_execution_time": f"{self.stats['total_execution_time'] / max(1, total):.2f}s",
            "active_tasks": len([t for t in self._tasks.values() if t.status == ExecutionStatus.RUNNING])
        }

    async def get_task_status(self, task_id: str) -> Optional[TaskInfo]:
        """获取任务状态"""
        async with self._lock:
            return self._tasks.get(task_id)

    async def cancel_task(self, task_id: str) -> bool:
        """取消任务(如果还在运行)"""
        async with self._lock:
            task_info = self._tasks.get(task_id)
            if task_info and task_info.status == ExecutionStatus.RUNNING:
                task_info.status = ExecutionStatus.CANCELLED
                return True
            return False

    async def cleanup_completed_tasks(self, max_age: int = 3600):
        """清理已完成的任务记录"""
        current_time = time.time()
        async with self._lock:
            to_remove = [
                task_id for task_id, info in self._tasks.items()
                if info.end_time and (current_time - info.end_time) > max_age
            ]
            for task_id in to_remove:
                del self._tasks[task_id]

            if to_remove:
                logger.debug(f"清理了 {len(to_remove)} 个过期任务记录")


# 全局执行器实例
_global_executor: Optional[AsyncExecutor] = None


def get_executor() -> AsyncExecutor:
    """获取全局执行器实例"""
    global _global_executor
    if _global_executor is None:
        _global_executor = AsyncExecutor()
    return _global_executor


async def execute_command(command: str, timeout: int = 300) -> ExecutionResult:
    """便捷函数: 执行单个命令"""
    return await get_executor().run_command(command, timeout=timeout)


async def execute_parallel(commands: List[str], timeout: int = 300) -> List[ExecutionResult]:
    """便捷函数: 并行执行多个命令"""
    return await get_executor().run_parallel(commands, timeout=timeout)
