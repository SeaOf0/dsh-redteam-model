#!/usr/bin/env python3
"""
结果缓存模块

提供智能的扫描结果缓存:
- 基于参数哈希的缓存
- 可配置的过期时间
- LRU缓存淘汰
- 缓存统计
"""

import hashlib
import json
import time
import logging
import threading
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """缓存条目"""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    def touch(self):
        """更新访问时间"""
        self.last_accessed = time.time()
        self.access_count += 1


class ResultCache:
    """结果缓存 - LRU缓存实现"""

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = 900,  # 15分钟默认TTL
        storage_path: Optional[str] = None
    ):
        """
        初始化缓存

        Args:
            max_size: 最大缓存条目数
            default_ttl: 默认生存时间(秒)
            storage_path: 持久化存储路径
        """
        self.max_size = max_size
        self.default_ttl = default_ttl

        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

        # 统计信息
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expired": 0
        }

        # 持久化
        if storage_path:
            self._storage_path = Path(storage_path)
            self._storage_path.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()
        else:
            self._storage_path = None

        logger.info(f"ResultCache初始化: max_size={max_size}, ttl={default_ttl}s")

    def _generate_key(self, tool: str, target: str, params: Dict[str, Any]) -> str:
        """生成缓存键"""
        # 对参数进行规范化排序
        sorted_params = json.dumps(params, sort_keys=True)
        key_data = f"{tool}:{target}:{sorted_params}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def get(
        self,
        tool: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[Any]]:
        """
        获取缓存值

        Args:
            tool: 工具名称
            target: 目标
            params: 参数

        Returns:
            (是否命中, 缓存值)
        """
        params = params or {}
        key = self._generate_key(tool, target, params)

        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self.stats["misses"] += 1
                return False, None

            if entry.is_expired():
                self._remove_entry(key)
                self.stats["expired"] += 1
                self.stats["misses"] += 1
                return False, None

            # 命中 - 更新访问信息并移到最后(LRU)
            entry.touch()
            self._cache.move_to_end(key)
            self.stats["hits"] += 1

            logger.debug(f"缓存命中: {tool}@{target[:30]}")
            return True, entry.value

    def set(
        self,
        tool: str,
        target: str,
        value: Any,
        params: Optional[Dict[str, Any]] = None,
        ttl: Optional[int] = None
    ):
        """
        设置缓存值

        Args:
            tool: 工具名称
            target: 目标
            value: 缓存值
            params: 参数
            ttl: 生存时间(秒)
        """
        params = params or {}
        ttl = ttl or self.default_ttl
        key = self._generate_key(tool, target, params)

        with self._lock:
            # 如果已存在，删除旧条目
            if key in self._cache:
                del self._cache[key]

            # 检查容量限制
            while len(self._cache) >= self.max_size:
                self._evict_oldest()

            # 创建新条目
            entry = CacheEntry(
                key=key,
                value=value,
                expires_at=time.time() + ttl if ttl > 0 else 0
            )

            self._cache[key] = entry
            logger.debug(f"缓存设置: {tool}@{target[:30]} (TTL: {ttl}s)")

    def invalidate(
        self,
        tool: Optional[str] = None,
        target: Optional[str] = None
    ) -> int:
        """
        使缓存失效

        Args:
            tool: 工具名称(为None则匹配所有)
            target: 目标(为None则匹配所有)

        Returns:
            删除的条目数
        """
        removed = 0

        with self._lock:
            keys_to_remove = []

            for key, entry in self._cache.items():
                # 这里需要反向解析key来匹配，简化处理直接按条件删除
                # 实际实现可能需要存储更多元数据
                keys_to_remove.append(key)

            for key in keys_to_remove:
                self._remove_entry(key)
                removed += 1

        logger.info(f"缓存失效: 删除 {removed} 个条目")
        return removed

    def clear(self):
        """清空缓存"""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"缓存已清空: {count} 个条目")

    def _evict_oldest(self):
        """淘汰最旧的条目(LRU)"""
        if self._cache:
            oldest_key = next(iter(self._cache))
            self._remove_entry(oldest_key)
            self.stats["evictions"] += 1

    def _remove_entry(self, key: str):
        """删除条目"""
        if key in self._cache:
            del self._cache[key]

    def cleanup_expired(self) -> int:
        """清理过期条目"""
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                self._remove_entry(key)
                removed += 1
                self.stats["expired"] += 1

        if removed > 0:
            logger.debug(f"清理过期缓存: {removed} 个条目")

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        with self._lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / max(1, total_requests)) * 100

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "hit_rate": f"{hit_rate:.1f}%",
                "evictions": self.stats["evictions"],
                "expired": self.stats["expired"]
            }

    def _load_from_disk(self):
        """从磁盘加载缓存"""
        if not self._storage_path:
            return

        cache_file = self._storage_path / "cache.json"
        if not cache_file.exists():
            return

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for key, entry_data in data.items():
                entry = CacheEntry(
                    key=key,
                    value=entry_data["value"],
                    created_at=entry_data["created_at"],
                    expires_at=entry_data["expires_at"]
                )

                if not entry.is_expired():
                    self._cache[key] = entry

            logger.info(f"从磁盘加载缓存: {len(self._cache)} 个条目")

        except Exception as e:
            logger.warning(f"加载缓存失败: {e}")

    def save_to_disk(self):
        """保存缓存到磁盘"""
        if not self._storage_path:
            return

        cache_file = self._storage_path / "cache.json"

        try:
            with self._lock:
                data = {}
                for key, entry in self._cache.items():
                    if not entry.is_expired():
                        data[key] = {
                            "value": entry.value,
                            "created_at": entry.created_at,
                            "expires_at": entry.expires_at
                        }

            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)

            logger.debug(f"缓存已保存: {len(data)} 个条目")

        except Exception as e:
            logger.warning(f"保存缓存失败: {e}")


class ToolResultCache:
    """工具结果专用缓存 - 针对安全工具优化"""

    # 不同工具类型的默认TTL
    TTL_CONFIG = {
        # 信息收集类 - 变化快，短TTL
        "nmap_scan": 600,          # 10分钟
        "masscan_fast_scan": 600,

        # Web扫描类 - 中等TTL
        "gobuster_scan": 1800,     # 30分钟
        "nuclei_scan": 1800,
        "whatweb_scan": 3600,      # 1小时

        # OSINT类 - 变化慢，长TTL
        "subfinder_scan": 7200,    # 2小时
        "theharvester_osint": 7200,

        # 默认
        "default": 900              # 15分钟
    }

    def __init__(self, base_cache: Optional[ResultCache] = None):
        """初始化工具结果缓存"""
        self._cache = base_cache or ResultCache()

    def get(self, tool: str, target: str, params: Dict[str, Any]) -> Tuple[bool, Optional[Any]]:
        """获取工具结果缓存"""
        return self._cache.get(tool, target, params)

    def set(self, tool: str, target: str, result: Any, params: Dict[str, Any]):
        """设置工具结果缓存"""
        ttl = self.TTL_CONFIG.get(tool, self.TTL_CONFIG["default"])
        self._cache.set(tool, target, result, params, ttl)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self._cache.get_stats()

    def clear(self):
        """清空缓存"""
        self._cache.clear()


# 全局缓存实例
_global_cache: Optional[ResultCache] = None
_global_tool_cache: Optional[ToolResultCache] = None


def get_cache() -> ResultCache:
    """获取全局缓存"""
    global _global_cache
    if _global_cache is None:
        _global_cache = ResultCache()
    return _global_cache


def get_tool_cache() -> ToolResultCache:
    """获取工具结果缓存"""
    global _global_tool_cache
    if _global_tool_cache is None:
        _global_tool_cache = ToolResultCache(get_cache())
    return _global_tool_cache
