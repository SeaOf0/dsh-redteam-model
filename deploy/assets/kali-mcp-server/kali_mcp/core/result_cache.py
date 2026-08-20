#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
结果缓存与去重系统 - Result Cache & Deduplication

解决问题:
- 重复调用相同工具浪费时间
- 同样的扫描多次执行
- 结果没有被复用

核心功能:
1. 结果缓存 - 相同目标+工具+参数的结果直接复用
2. 智能去重 - 自动检测重复扫描并跳过
3. 增量扫描 - 只扫描新发现的目标
4. 结果共享 - 工具间共享扫描结果
"""

import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
import threading


@dataclass
class CachedResult:
    """缓存的结果"""
    tool_name: str
    target: str
    params_hash: str
    result: Any
    timestamp: float
    execution_time: float
    hit_count: int = 0

    def is_expired(self, ttl_seconds: int = 3600) -> bool:
        """检查是否过期（默认1小时）"""
        return time.time() - self.timestamp > ttl_seconds

    def increment_hit(self):
        """增加命中计数"""
        self.hit_count += 1


class ResultCache:
    """
    结果缓存系统

    避免重复执行相同的扫描
    """

    # 不同工具的缓存有效期（秒）
    TOOL_TTL = {
        # 基础信息收集 - 较长缓存
        "nmap_scan": 7200,        # 2小时
        "masscan_fast_scan": 3600, # 1小时
        "whatweb_scan": 7200,     # 2小时
        "httpx_probe": 3600,      # 1小时
        "wafw00f_scan": 7200,     # 2小时

        # 目录扫描 - 中等缓存
        "gobuster_scan": 3600,    # 1小时
        "ffuf_scan": 3600,        # 1小时
        "feroxbuster_scan": 3600, # 1小时
        "dirb_scan": 3600,        # 1小时

        # 漏洞扫描 - 较短缓存
        "nuclei_scan": 1800,      # 30分钟
        "nuclei_web_scan": 1800,  # 30分钟
        "nikto_scan": 1800,       # 30分钟

        # 利用工具 - 不缓存或短缓存
        "sqlmap_scan": 600,       # 10分钟
        "hydra_attack": 0,        # 不缓存
        "metasploit_run": 0,      # 不缓存

        # 默认
        "default": 1800,          # 30分钟
    }

    def __init__(self, persist_path: str = None):
        """
        初始化缓存

        Args:
            persist_path: 持久化文件路径（可选）
        """
        self._cache: Dict[str, CachedResult] = {}
        self._lock = threading.RLock()
        self.persist_path = persist_path

        # 统计信息
        self.stats = {
            "hits": 0,
            "misses": 0,
            "saves": 0,
            "evictions": 0,
        }

        # 加载持久化缓存
        if persist_path:
            self._load_cache()

    def _generate_key(self, tool_name: str, target: str,
                     params: Dict = None) -> str:
        """生成缓存键"""
        params_str = json.dumps(params or {}, sort_keys=True)
        key_str = f"{tool_name}:{target}:{params_str}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, tool_name: str, target: str,
            params: Dict = None) -> Optional[CachedResult]:
        """
        获取缓存结果

        Returns:
            CachedResult if found and valid, None otherwise
        """
        key = self._generate_key(tool_name, target, params)

        with self._lock:
            if key in self._cache:
                cached = self._cache[key]
                ttl = self.TOOL_TTL.get(tool_name, self.TOOL_TTL["default"])

                if ttl == 0:
                    # 不缓存的工具
                    self.stats["misses"] += 1
                    return None

                if not cached.is_expired(ttl):
                    cached.increment_hit()
                    self.stats["hits"] += 1
                    return cached
                else:
                    # 过期，删除
                    del self._cache[key]
                    self.stats["evictions"] += 1

            self.stats["misses"] += 1
            return None

    def set(self, tool_name: str, target: str, params: Dict,
            result: Any, execution_time: float):
        """存储结果到缓存"""
        ttl = self.TOOL_TTL.get(tool_name, self.TOOL_TTL["default"])

        if ttl == 0:
            # 不缓存此工具的结果
            return

        key = self._generate_key(tool_name, target, params)
        params_hash = hashlib.md5(json.dumps(params or {}, sort_keys=True).encode()).hexdigest()[:8]

        with self._lock:
            self._cache[key] = CachedResult(
                tool_name=tool_name,
                target=target,
                params_hash=params_hash,
                result=result,
                timestamp=time.time(),
                execution_time=execution_time,
            )
            self.stats["saves"] += 1

        # 持久化
        if self.persist_path:
            self._save_cache()

    def invalidate(self, tool_name: str = None, target: str = None):
        """
        使缓存失效

        Args:
            tool_name: 指定工具（可选）
            target: 指定目标（可选）
        """
        with self._lock:
            keys_to_delete = []

            for key, cached in self._cache.items():
                if tool_name and cached.tool_name != tool_name:
                    continue
                if target and cached.target != target:
                    continue
                keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._cache[key]
                self.stats["evictions"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        with self._lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = self.stats["hits"] / total_requests * 100 if total_requests > 0 else 0

            return {
                "cache_size": len(self._cache),
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "hit_rate": f"{hit_rate:.1f}%",
                "saves": self.stats["saves"],
                "evictions": self.stats["evictions"],
                "time_saved_estimate": sum(
                    c.execution_time * c.hit_count
                    for c in self._cache.values()
                ),
            }

    def _save_cache(self):
        """持久化缓存到文件"""
        if not self.persist_path:
            return

        try:
            data = {
                key: {
                    "tool_name": c.tool_name,
                    "target": c.target,
                    "params_hash": c.params_hash,
                    "result": str(c.result)[:10000],  # 限制大小
                    "timestamp": c.timestamp,
                    "execution_time": c.execution_time,
                    "hit_count": c.hit_count,
                }
                for key, c in self._cache.items()
            }

            Path(self.persist_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"[!] 缓存持久化失败: {e}")

    def _load_cache(self):
        """从文件加载缓存"""
        if not self.persist_path or not Path(self.persist_path).exists():
            return

        try:
            with open(self.persist_path, 'r') as f:
                data = json.load(f)

            for key, item in data.items():
                self._cache[key] = CachedResult(
                    tool_name=item["tool_name"],
                    target=item["target"],
                    params_hash=item["params_hash"],
                    result=item["result"],
                    timestamp=item["timestamp"],
                    execution_time=item["execution_time"],
                    hit_count=item.get("hit_count", 0),
                )
        except Exception as e:
            print(f"[!] 缓存加载失败: {e}")


class ScanDeduplicator:
    """
    扫描去重器

    防止重复执行相同的扫描
    """

    # 可以合并的扫描类型
    MERGEABLE_SCANS = {
        # 端口扫描 - nmap的不同扫描可以合并
        "port_scan": ["nmap_scan", "masscan_fast_scan"],
        # 目录扫描 - 使用最全面的结果
        "dir_scan": ["gobuster_scan", "ffuf_scan", "feroxbuster_scan", "dirb_scan"],
        # 漏洞扫描
        "vuln_scan": ["nuclei_scan", "nuclei_web_scan", "nuclei_cve_scan"],
        # DNS枚举
        "dns_enum": ["dnsrecon_scan", "dnsenum_scan", "fierce_scan"],
    }

    # 参数等价性规则
    PARAM_EQUIVALENCE = {
        "nmap_scan": {
            # 如果已经做了全端口扫描，就不需要做部分端口扫描
            "ports": lambda old, new: old == "1-65535" or old == new,
            # 如果已经做了版本扫描，就不需要再做
            "scan_type": lambda old, new: "-sV" in old if "-sV" in new else True,
        },
        "gobuster_scan": {
            # 如果已经用了大字典，就不需要再用小字典
            "wordlist": lambda old, new: "big" in old or "large" in old if "common" in new else old == new,
        },
    }

    def __init__(self):
        self.executed_scans: Dict[str, Dict] = {}  # target -> {tool -> params}
        self.scan_results: Dict[str, Dict] = {}     # target -> {tool -> result}

    def should_skip(self, tool_name: str, target: str,
                   params: Dict = None) -> Tuple[bool, Optional[str]]:
        """
        检查是否应该跳过此扫描

        Returns:
            (should_skip, reason)
        """
        params = params or {}

        if target not in self.executed_scans:
            return False, None

        target_scans = self.executed_scans[target]

        # 检查完全相同的扫描
        if tool_name in target_scans:
            old_params = target_scans[tool_name]

            # 检查参数等价性
            if self._params_equivalent(tool_name, old_params, params):
                return True, f"已执行相同的{tool_name}扫描"

        # 检查可合并的扫描
        for scan_group, tools in self.MERGEABLE_SCANS.items():
            if tool_name in tools:
                for other_tool in tools:
                    if other_tool in target_scans and other_tool != tool_name:
                        # 如果同组的其他工具已执行，检查是否覆盖
                        if self._scan_covered(tool_name, other_tool,
                                            params, target_scans[other_tool]):
                            return True, f"{other_tool}已覆盖此扫描"

        return False, None

    def _params_equivalent(self, tool_name: str,
                          old_params: Dict, new_params: Dict) -> bool:
        """检查参数是否等价"""
        if tool_name not in self.PARAM_EQUIVALENCE:
            return old_params == new_params

        rules = self.PARAM_EQUIVALENCE[tool_name]

        for param, check_func in rules.items():
            old_val = old_params.get(param, "")
            new_val = new_params.get(param, "")

            if not check_func(old_val, new_val):
                return False

        return True

    def _scan_covered(self, new_tool: str, old_tool: str,
                     new_params: Dict, old_params: Dict) -> bool:
        """检查旧扫描是否覆盖了新扫描"""
        # 简化逻辑：如果是同类工具且旧扫描参数更激进，则认为已覆盖

        # 端口扫描
        if old_tool == "nmap_scan" and new_tool == "masscan_fast_scan":
            if old_params.get("ports") == "1-65535":
                return True

        # 目录扫描
        dir_tools = ["gobuster_scan", "ffuf_scan", "feroxbuster_scan"]
        if old_tool in dir_tools and new_tool in dir_tools:
            old_wordlist = old_params.get("wordlist", "")
            new_wordlist = new_params.get("wordlist", "")
            if ("big" in old_wordlist or "large" in old_wordlist) and "common" in new_wordlist:
                return True

        return False

    def record_scan(self, tool_name: str, target: str,
                   params: Dict, result: Any):
        """记录已执行的扫描"""
        if target not in self.executed_scans:
            self.executed_scans[target] = {}
            self.scan_results[target] = {}

        self.executed_scans[target][tool_name] = params
        self.scan_results[target][tool_name] = result

    def get_previous_result(self, tool_name: str, target: str) -> Optional[Any]:
        """获取之前的扫描结果"""
        if target in self.scan_results and tool_name in self.scan_results[target]:
            return self.scan_results[target][tool_name]
        return None

    def get_merged_results(self, target: str, scan_type: str) -> Dict[str, Any]:
        """获取合并的扫描结果"""
        if scan_type not in self.MERGEABLE_SCANS:
            return {}

        tools = self.MERGEABLE_SCANS[scan_type]
        merged = {}

        if target in self.scan_results:
            for tool in tools:
                if tool in self.scan_results[target]:
                    merged[tool] = self.scan_results[target][tool]

        return merged


class IncrementalScanner:
    """
    增量扫描器

    只扫描新发现的目标，避免重复扫描
    """

    def __init__(self):
        self.scanned_targets: Dict[str, Set[str]] = defaultdict(set)
        self.discovered_assets: Dict[str, List] = defaultdict(list)

    def get_new_targets(self, targets: List[str],
                       scan_type: str) -> List[str]:
        """
        获取未扫描过的目标

        Args:
            targets: 目标列表
            scan_type: 扫描类型

        Returns:
            未扫描过的目标列表
        """
        scanned = self.scanned_targets[scan_type]
        new_targets = [t for t in targets if t not in scanned]
        return new_targets

    def mark_scanned(self, targets: List[str], scan_type: str):
        """标记目标已扫描"""
        self.scanned_targets[scan_type].update(targets)

    def add_discovered_assets(self, asset_type: str, assets: List):
        """添加发现的资产"""
        for asset in assets:
            if asset not in self.discovered_assets[asset_type]:
                self.discovered_assets[asset_type].append(asset)

    def get_new_assets(self, asset_type: str,
                      known_assets: List = None) -> List:
        """获取新发现的资产"""
        known = set(known_assets or [])
        return [a for a in self.discovered_assets[asset_type] if a not in known]


class SmartScanOptimizer:
    """
    智能扫描优化器

    综合使用缓存、去重和增量扫描
    """

    def __init__(self, cache_path: str = None):
        self.cache = ResultCache(cache_path)
        self.deduplicator = ScanDeduplicator()
        self.incremental = IncrementalScanner()

        # 优化统计
        self.optimization_stats = {
            "scans_skipped": 0,
            "cache_hits": 0,
            "time_saved_seconds": 0,
        }

    async def optimized_execute(self, tool_name: str, target: str,
                                params: Dict, execute_func) -> Tuple[Any, bool]:
        """
        优化执行工具

        Returns:
            (result, was_cached)
        """
        # 1. 检查缓存
        cached = self.cache.get(tool_name, target, params)
        if cached:
            print(f"    [缓存命中] {tool_name} - 节省 {cached.execution_time:.1f}秒")
            self.optimization_stats["cache_hits"] += 1
            self.optimization_stats["time_saved_seconds"] += cached.execution_time
            return cached.result, True

        # 2. 检查去重
        should_skip, reason = self.deduplicator.should_skip(tool_name, target, params)
        if should_skip:
            print(f"    [跳过] {tool_name} - {reason}")
            self.optimization_stats["scans_skipped"] += 1
            # 返回之前的结果
            prev_result = self.deduplicator.get_previous_result(tool_name, target)
            return prev_result, True

        # 3. 执行扫描
        start_time = time.time()
        result = await execute_func(tool_name, target, params)
        execution_time = time.time() - start_time

        # 4. 存储结果
        self.cache.set(tool_name, target, params, result, execution_time)
        self.deduplicator.record_scan(tool_name, target, params, result)

        return result, False

    def get_optimization_report(self) -> Dict[str, Any]:
        """获取优化报告"""
        cache_stats = self.cache.get_stats()

        return {
            "cache_stats": cache_stats,
            "scans_skipped": self.optimization_stats["scans_skipped"],
            "total_time_saved_seconds": self.optimization_stats["time_saved_seconds"],
            "total_time_saved_minutes": self.optimization_stats["time_saved_seconds"] / 60,
        }

    def suggest_optimizations(self, planned_scans: List[Dict]) -> List[Dict]:
        """
        分析计划的扫描并建议优化

        Returns:
            优化后的扫描计划
        """
        optimized = []
        skip_count = 0

        for scan in planned_scans:
            tool_name = scan.get("tool")
            target = scan.get("target")
            params = scan.get("params", {})

            # 检查是否可以跳过
            should_skip, reason = self.deduplicator.should_skip(tool_name, target, params)

            if should_skip:
                skip_count += 1
                scan["status"] = "skip"
                scan["skip_reason"] = reason
            else:
                scan["status"] = "execute"

            optimized.append(scan)

        print(f"[优化] 可跳过 {skip_count}/{len(planned_scans)} 个扫描")

        return optimized

    async def smart_scan(self, target: str, tools: List[str],
                         use_cache: bool = True, cache_ttl: int = 3600) -> Dict[str, Any]:
        """
        智能扫描 - 自动去重和缓存

        Args:
            target: 目标
            tools: 要执行的工具列表
            use_cache: 是否使用缓存
            cache_ttl: 缓存有效期(秒)

        Returns:
            扫描结果
        """
        results = {
            "target": target,
            "tools_requested": tools,
            "results": {},
            "cache_hits": [],
            "executed": [],
            "skipped": []
        }

        for tool_name in tools:
            params = {"target": target}

            # 检查缓存
            if use_cache:
                cached = self.cache.get(tool_name, target, params)
                if cached:
                    results["results"][tool_name] = cached.result
                    results["cache_hits"].append(tool_name)
                    continue

            # 检查去重
            should_skip, reason = self.deduplicator.should_skip(tool_name, target, params)
            if should_skip:
                prev_result = self.deduplicator.get_previous_result(tool_name, target)
                results["results"][tool_name] = prev_result
                results["skipped"].append({"tool": tool_name, "reason": reason})
                continue

            # 需要执行的工具记录下来
            results["executed"].append(tool_name)
            results["results"][tool_name] = {
                "status": "pending",
                "message": f"工具 {tool_name} 需要执行，请使用对应的MCP工具"
            }

        results["summary"] = {
            "total_tools": len(tools),
            "cache_hits": len(results["cache_hits"]),
            "skipped": len(results["skipped"]),
            "need_execution": len(results["executed"])
        }

        return results


# 全局优化器实例
_global_optimizer: Optional[SmartScanOptimizer] = None


def get_optimizer() -> SmartScanOptimizer:
    """获取全局优化器"""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = SmartScanOptimizer(
            cache_path="/tmp/kali_mcp_cache.json"
        )
    return _global_optimizer


# 导出
__all__ = [
    "ResultCache",
    "ScanDeduplicator",
    "IncrementalScanner",
    "SmartScanOptimizer",
    "get_optimizer",
    "CachedResult",
]
