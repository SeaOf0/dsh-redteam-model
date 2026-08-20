#!/usr/bin/env python3
"""
KaliMCP 连接池优化模块
复用HTTP连接避免重复握手，大幅减少连接开销
"""

import requests
import time
import threading
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)

class OptimizedHTTPSession:
    """优化的HTTP会话，支持连接池和重试机制"""

    def __init__(self, pool_connections=10, pool_maxsize=20, max_retries=1, backoff_factor=0.1):
        """
        初始化优化的HTTP会话

        Args:
            pool_connections: 连接池大小
            pool_maxsize: 每个主机的最大连接数
            max_retries: 最大重试次数
            backoff_factor: 重试延迟因子
        """
        self.session = requests.Session()

        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )

        # 配置HTTP适配器
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # 设置默认头部
        self.session.headers.update({
            'User-Agent': 'KaliMCP-Client/1.0',
            'Connection': 'keep-alive',
            'Accept': 'application/json'
        })

        logger.info(f"初始化HTTP连接池: connections={pool_connections}, maxsize={pool_maxsize}")

    def get(self, url: str, timeout: int = 10, **kwargs) -> requests.Response:
        """执行GET请求"""
        return self.session.get(url, timeout=timeout, **kwargs)

    def post(self, url: str, timeout: int = 10, **kwargs) -> requests.Response:
        """执行POST请求"""
        return self.session.post(url, timeout=timeout, **kwargs)

    def close(self):
        """关闭会话"""
        self.session.close()


class ConnectionPoolManager:
    """连接池管理器，为不同主机维护独立的连接池"""

    def __init__(self):
        self.pools: Dict[str, OptimizedHTTPSession] = {}
        self.lock = threading.Lock()
        self.stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'connection_reuse': 0
        }

    def get_session(self, base_url: str) -> OptimizedHTTPSession:
        """获取或创建指定主机的HTTP会话"""
        with self.lock:
            if base_url not in self.pools:
                self.pools[base_url] = OptimizedHTTPSession()
                logger.info(f"为主机创建新的连接池: {base_url}")
            else:
                self.stats['connection_reuse'] += 1

            return self.pools[base_url]

    def get_stats(self) -> Dict[str, Any]:
        """获取连接池统计信息"""
        return {
            'active_pools': len(self.pools),
            'total_requests': self.stats['total_requests'],
            'cache_hits': self.stats['cache_hits'],
            'connection_reuse': self.stats['connection_reuse'],
            'reuse_rate': f"{(self.stats['connection_reuse'] / max(1, self.stats['total_requests'])) * 100:.1f}%"
        }

    def cleanup_idle_pools(self, max_idle_time: int = 300):
        """清理空闲连接池"""
        # 简化版本，实际实现需要跟踪最后使用时间
        with self.lock:
            for base_url, session in list(self.pools.items()):
                # 这里可以添加空闲时间检查逻辑
                pass

    def close_all(self):
        """关闭所有连接池"""
        with self.lock:
            for session in self.pools.values():
                session.close()
            self.pools.clear()
            logger.info("所有连接池已关闭")


# 全局连接池管理器实例
_connection_pool_manager = ConnectionPoolManager()

def get_connection_pool() -> ConnectionPoolManager:
    """获取全局连接池管理器"""
    return _connection_pool_manager

def optimized_request(method: str, url: str, timeout: int = 10, **kwargs) -> requests.Response:
    """
    使用连接池的优化请求函数

    Args:
        method: HTTP方法 (GET, POST, etc.)
        url: 完整URL
        timeout: 超时时间
        **kwargs: 其他请求参数

    Returns:
        requests.Response对象
    """
    # 提取基础URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 获取连接池
    pool_manager = get_connection_pool()
    session = pool_manager.get_session(base_url)

    # 执行请求
    pool_manager.stats['total_requests'] += 1

    if method.upper() == 'GET':
        return session.get(url, timeout=timeout, **kwargs)
    elif method.upper() == 'POST':
        return session.post(url, timeout=timeout, **kwargs)
    else:
        # 回退到原始requests
        return requests.request(method, url, timeout=timeout, **kwargs)