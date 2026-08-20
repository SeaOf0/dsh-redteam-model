#!/usr/bin/env python3
"""
Kali MCP 工具模块 v2.0

提供统一的工具注册和管理:
- 工具自动发现和注册
- 分类管理
- 统一执行接口

新增 (v2.0):
- AD攻击工具包: Kerberos攻击、横向移动、凭据提取
- 取证与隐写术: 文件分析、内存取证、隐写检测
- 移动安全: APK/IPA分析、Frida动态分析
- 云安全: AWS/Azure/GCP安全评估 (如可用)
- 容器安全: Docker/K8s安全扫描 (如可用)
"""

from .base import (
    BaseTool,
    ToolResult,
    ToolCategory,
    ToolRegistry,
    tool,
    get_registry
)

# AD攻击工具包
try:
    from .ad import (
        ADEnumerator,
        KerberosAttacks,
        CredentialDumping,
        LateralMovement,
        ADPersistence,
        ADAttackOrchestrator,
    )
    AD_TOOLS_AVAILABLE = True
except ImportError:
    AD_TOOLS_AVAILABLE = False

# 取证与隐写术工具包
try:
    from .forensics import (
        FileAnalyzer,
        SteganographyDetector,
        MemoryForensics,
        NetworkForensics,
        CTFMiscSolver,
    )
    FORENSICS_TOOLS_AVAILABLE = True
except ImportError:
    FORENSICS_TOOLS_AVAILABLE = False

# 移动安全工具包
try:
    from .mobile import (
        APKAnalyzer,
        IOSAnalyzer,
        MobSFAnalyzer,
        FridaHooker,
        MobileSecurityScanner,
    )
    MOBILE_TOOLS_AVAILABLE = True
except ImportError:
    MOBILE_TOOLS_AVAILABLE = False

# 云安全工具包 (可选)
try:
    from .cloud import (
        AWSSecurityScanner,
        AzureSecurityScanner,
        GCPSecurityScanner,
        CloudAttackOrchestrator,
    )
    CLOUD_TOOLS_AVAILABLE = True
except ImportError:
    CLOUD_TOOLS_AVAILABLE = False

# 容器安全工具包 (可选)
try:
    from .container import (
        DockerSecurityScanner,
        KubernetesSecurityScanner,
        ContainerEscapeDetector,
        ContainerSecurityOrchestrator,
    )
    CONTAINER_TOOLS_AVAILABLE = True
except ImportError:
    CONTAINER_TOOLS_AVAILABLE = False

__all__ = [
    # 基础工具类
    "BaseTool",
    "ToolResult",
    "ToolCategory",
    "ToolRegistry",
    "tool",
    "get_registry",

    # AD攻击工具
    "ADEnumerator",
    "KerberosAttacks",
    "CredentialDumping",
    "LateralMovement",
    "ADPersistence",
    "ADAttackOrchestrator",

    # 取证与隐写术
    "FileAnalyzer",
    "SteganographyDetector",
    "MemoryForensics",
    "NetworkForensics",
    "CTFMiscSolver",

    # 移动安全
    "APKAnalyzer",
    "IOSAnalyzer",
    "MobSFAnalyzer",
    "FridaHooker",
    "MobileSecurityScanner",

    # 云安全
    "AWSSecurityScanner",
    "AzureSecurityScanner",
    "GCPSecurityScanner",
    "CloudAttackOrchestrator",

    # 容器安全
    "DockerSecurityScanner",
    "KubernetesSecurityScanner",
    "ContainerEscapeDetector",
    "ContainerSecurityOrchestrator",

    # 可用性标志
    "AD_TOOLS_AVAILABLE",
    "FORENSICS_TOOLS_AVAILABLE",
    "MOBILE_TOOLS_AVAILABLE",
    "CLOUD_TOOLS_AVAILABLE",
    "CONTAINER_TOOLS_AVAILABLE",
]

# 版本信息
__version__ = "2.0.0"
__description__ = "Kali MCP 工具模块 - 全覆盖安全测试工具集"
