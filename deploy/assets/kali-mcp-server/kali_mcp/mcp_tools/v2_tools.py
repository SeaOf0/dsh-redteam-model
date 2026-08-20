#!/usr/bin/env python3
"""
Kali MCP 工具 v2.2 - 新增MCP工具注册

包含:
- 终极扫描引擎工具
- 智能编排工具
- AD攻击工具
- 取证与隐写术工具
- 移动安全工具
- 智能缓存工具

新增 (v2.2) - - CTF POC扫描引擎
- CTF 多Agent协作框架
- CTF 知识库驱动检测
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# 导入核心模块
try:
    from kali_mcp.core import (
        ULTIMATE_ENGINE_AVAILABLE,
        ORCHESTRATOR_AVAILABLE,
        OPTIMIZER_AVAILABLE,
        SKILL_DISPATCHER_AVAILABLE,
        CTF_POC_ENGINE_AVAILABLE,
        CTF_AGENT_FRAMEWORK_AVAILABLE,
        CTF_KNOWLEDGE_BASE_AVAILABLE,
    )
    if ULTIMATE_ENGINE_AVAILABLE:
        from kali_mcp.core.ultimate_engine import UltimateScanEngine, CTFUltimateSolver, TargetType, ScanPhase, IterationLevel
    if ORCHESTRATOR_AVAILABLE:
        from kali_mcp.core.tool_orchestrator import ToolOrchestrator, AutoPilotAttack, ToolCategory, TriggerCondition
    if OPTIMIZER_AVAILABLE:
        from kali_mcp.core.result_cache import ScanDeduplicator, SmartScanOptimizer, get_optimizer
except ImportError as e:
    logger.warning(f"核心模块导入失败: {e}")
    ULTIMATE_ENGINE_AVAILABLE = False
    ORCHESTRATOR_AVAILABLE = False
    OPTIMIZER_AVAILABLE = False
    SKILL_DISPATCHER_AVAILABLE = False
    CTF_POC_ENGINE_AVAILABLE = False
    CTF_AGENT_FRAMEWORK_AVAILABLE = False
    CTF_KNOWLEDGE_BASE_AVAILABLE = False

# 导入CTF模块 (v2.2) - try:
    if CTF_POC_ENGINE_AVAILABLE:
        from kali_mcp.core.ctf_poc_engine import POCScanner, POCManager, get_poc_manager, quick_poc_scan
        # 兼容性别名
        scan_with_pocs = quick_poc_scan
    if CTF_AGENT_FRAMEWORK_AVAILABLE:
        from kali_mcp.core.ctf_agent_framework import CTFCoordinator, create_ctf_coordinator, quick_ctf_solve, FlagDetector
        # 兼容性别名
        create_ctf_solver = create_ctf_coordinator
        solve_ctf = quick_ctf_solve
    if CTF_KNOWLEDGE_BASE_AVAILABLE:
        from kali_mcp.core.ctf_knowledge_base import (
            CTFKnowledgeBase, KnowledgeDrivenDetector, get_knowledge_base,
            get_payloads, get_flag_getters, detect_flags, suggest_action
        )
except ImportError as e:
    logger.warning(f"CTF模块导入失败: {e}")
    CTF_POC_ENGINE_AVAILABLE = False
    CTF_AGENT_FRAMEWORK_AVAILABLE = False
    CTF_KNOWLEDGE_BASE_AVAILABLE = False

# 导入工具模块
try:
    from kali_mcp.tools import (
        AD_TOOLS_AVAILABLE,
        FORENSICS_TOOLS_AVAILABLE,
        MOBILE_TOOLS_AVAILABLE,
    )
    if AD_TOOLS_AVAILABLE:
        from kali_mcp.tools.ad import ADAttackOrchestrator
    if FORENSICS_TOOLS_AVAILABLE:
        from kali_mcp.tools.forensics import FileAnalyzer, SteganographyDetector, MemoryForensics, NetworkForensics, CTFMiscSolver
    if MOBILE_TOOLS_AVAILABLE:
        from kali_mcp.tools.mobile import MobileSecurityScanner
except ImportError as e:
    logger.warning(f"工具模块导入失败: {e}")
    AD_TOOLS_AVAILABLE = False
    FORENSICS_TOOLS_AVAILABLE = False
    MOBILE_TOOLS_AVAILABLE = False

# 全局实例
_ultimate_engine = None
_tool_orchestrator = None
_scan_optimizer = None
_ad_orchestrator = None
_forensics_orchestrator = None
_mobile_scanner = None
# CTF模块实例 (v2.2)
_poc_manager = None
_ctf_coordinator = None
_knowledge_base = None


def get_ultimate_engine():
    """获取终极扫描引擎单例"""
    global _ultimate_engine
    if _ultimate_engine is None and ULTIMATE_ENGINE_AVAILABLE:
        _ultimate_engine = UltimateScanEngine()
    return _ultimate_engine


def get_tool_orchestrator():
    """获取工具编排器单例"""
    global _tool_orchestrator
    if _tool_orchestrator is None and ORCHESTRATOR_AVAILABLE:
        _tool_orchestrator = ToolOrchestrator()
    return _tool_orchestrator


def get_scan_optimizer():
    """获取扫描优化器单例"""
    global _scan_optimizer
    if _scan_optimizer is None and OPTIMIZER_AVAILABLE:
        _scan_optimizer = SmartScanOptimizer()
    return _scan_optimizer


def get_ad_orchestrator(domain: str = None, dc_ip: str = None,
                        username: str = None, password: str = None,
                        ntlm_hash: str = None):
    """获取AD攻击编排器 - 按需创建，支持不同目标"""
    if not AD_TOOLS_AVAILABLE:
        return None

    # 每次根据参数创建新实例（不同攻击可能针对不同域）
    if domain and dc_ip:
        return ADAttackOrchestrator(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash
        )

    # 返回一个懒加载的代理对象
    return _ADOrchestratorProxy()


class _ADOrchestratorProxy:
    """AD编排器代理 - 延迟初始化"""

    async def full_ad_attack(self, target_dc: str, domain: str,
                            username: str = None, password: str = None,
                            attack_mode: str = "comprehensive"):
        orchestrator = ADAttackOrchestrator(
            domain=domain, dc_ip=target_dc,
            username=username, password=password
        )
        return orchestrator.run_full_assessment()

    async def kerberoast(self, target_dc: str, domain: str,
                        username: str = "", password: str = "",
                        output_format: str = "hashcat"):
        orchestrator = ADAttackOrchestrator(
            domain=domain, dc_ip=target_dc,
            username=username if username else None,
            password=password if password else None
        )
        return orchestrator.kerberos.kerberoast(
            output_format=output_format
        )

    async def dcsync(self, target_dc: str, domain: str,
                    username: str, password: str,
                    target_user: str = "Administrator"):
        orchestrator = ADAttackOrchestrator(
            domain=domain, dc_ip=target_dc,
            username=username, password=password
        )
        return orchestrator.cred_dump.dcsync(target_user=target_user)


class _ForensicsWrapper:
    """取证工具包装器 - 提供统一接口"""

    def __init__(self):
        self.file_analyzer = FileAnalyzer() if FORENSICS_TOOLS_AVAILABLE else None
        self.stego_detector = SteganographyDetector() if FORENSICS_TOOLS_AVAILABLE else None
        self.memory_forensics = MemoryForensics() if FORENSICS_TOOLS_AVAILABLE else None
        self.network_forensics = NetworkForensics() if FORENSICS_TOOLS_AVAILABLE else None

    async def full_analysis(self, target_path: str, analysis_type: str = "auto"):
        """全面取证分析"""
        if not FORENSICS_TOOLS_AVAILABLE:
            return {"error": "取证工具不可用"}

        results = {"target": target_path, "analysis_type": analysis_type, "findings": []}

        # 文件分析 - 使用get_file_info（同步方法）
        if self.file_analyzer:
            try:
                file_info = self.file_analyzer.get_file_info(target_path)
                results["file_analysis"] = {
                    "path": file_info.path,
                    "size": file_info.size,
                    "md5": file_info.md5,
                    "sha256": file_info.sha256,
                    "file_type": file_info.file_type
                }
            except Exception as e:
                results["file_analysis"] = {"error": str(e)}

        # 隐写检测 - detect是同步方法，不需要await
        if self.stego_detector and analysis_type in ["auto", "steganography"]:
            stego_result = self.stego_detector.detect(target_path)
            results["steganography"] = stego_result

        return results

    async def detect_steganography(self, file_path: str, extract_data: bool = True, password: str = ""):
        """隐写术检测"""
        if not self.stego_detector:
            return {"error": "隐写检测器不可用"}
        # detect是同步方法，不需要await
        return self.stego_detector.detect(file_path, extract=extract_data, password=password)

    async def analyze_memory(self, dump_path: str, profile: str = "auto"):
        """内存分析"""
        if not self.memory_forensics:
            return {"error": "内存取证工具不可用"}
        # 使用volatility_analyze而不是analyze（同步方法）
        return self.memory_forensics.volatility_analyze(dump_path, profile=profile if profile != "auto" else None)


def get_forensics_orchestrator():
    """获取取证编排器单例"""
    global _forensics_orchestrator
    if _forensics_orchestrator is None and FORENSICS_TOOLS_AVAILABLE:
        _forensics_orchestrator = _ForensicsWrapper()
    return _forensics_orchestrator


def get_mobile_scanner():
    """获取移动安全扫描器单例"""
    global _mobile_scanner
    if _mobile_scanner is None and MOBILE_TOOLS_AVAILABLE:
        _mobile_scanner = MobileSecurityScanner()
    return _mobile_scanner


# CTF模块单例获取函数 (v2.2)
def get_ctf_poc_manager():
    """获取CTF POC管理器单例"""
    global _poc_manager
    if _poc_manager is None and CTF_POC_ENGINE_AVAILABLE:
        _poc_manager = get_poc_manager()
    return _poc_manager


def get_ctf_coordinator():
    """获取CTF协调器单例"""
    global _ctf_coordinator
    if _ctf_coordinator is None and CTF_AGENT_FRAMEWORK_AVAILABLE:
        _ctf_coordinator = CTFCoordinator()
    return _ctf_coordinator


def get_ctf_knowledge_base():
    """获取CTF知识库单例"""
    global _knowledge_base
    if _knowledge_base is None and CTF_KNOWLEDGE_BASE_AVAILABLE:
        _knowledge_base = get_knowledge_base()
    return _knowledge_base


def register_v2_tools(mcp, executor):
    """
    注册所有v2.0 MCP工具

    Args:
        mcp: FastMCP实例
        executor: 命令执行器
    """

    # ==================== 终极扫描引擎工具 ====================

    @mcp.tool()
    async def ultimate_scan(
        target: str,
        target_type: str = "auto",
        iteration_level: str = "standard",
        enable_exploitation: bool = False
    ) -> Dict[str, Any]:
        """
        终极扫描引擎 - 100%工具覆盖的全面安全评估

        执行多轮迭代扫描，确保没有遗漏任何漏洞:
        - 第1轮: 快速扫描，建立基础信息
        - 第2轮: 深度扫描，基于第1轮结果
        - 第3轮: 精确验证，确认发现的漏洞
        - 第4轮(可选): 穷尽扫描，覆盖所有边缘情况

        Args:
            target: 目标URL、IP或域名
            target_type: 目标类型 (auto, web, network, api, database, mobile, iot, ad)
            iteration_level: 迭代级别 (quick, standard, thorough, exhaustive)
            enable_exploitation: 是否启用自动漏洞利用

        Returns:
            完整的安全评估结果，包含所有发现的漏洞和建议
        """
        if not ULTIMATE_ENGINE_AVAILABLE:
            return {"error": "终极扫描引擎不可用", "suggestion": "请检查 ultimate_engine.py 是否正确安装"}

        engine = get_ultimate_engine()

        # 解析目标类型
        type_mapping = {
            "auto": TargetType.WEB_APPLICATION,  # 默认
            "web": TargetType.WEB_APPLICATION,
            "network": TargetType.NETWORK_SERVICE,
            "api": TargetType.API_SERVICE,
            "database": TargetType.DATABASE,
            "mobile": TargetType.MOBILE_APP,
            "iot": TargetType.IOT_DEVICE,
            "ad": TargetType.ACTIVE_DIRECTORY,
        }
        parsed_type = type_mapping.get(target_type, TargetType.WEB_APPLICATION)

        # 解析迭代级别
        level_mapping = {
            "quick": IterationLevel.QUICK,
            "standard": IterationLevel.STANDARD,
            "thorough": IterationLevel.THOROUGH,
            "exhaustive": IterationLevel.EXHAUSTIVE,
        }
        parsed_level = level_mapping.get(iteration_level, IterationLevel.STANDARD)

        # 执行终极扫描
        result = await engine.execute_ultimate_scan(
            target=target,
            target_type=parsed_type,
            iteration_level=parsed_level,
            enable_exploitation=enable_exploitation
        )

        return result

    @mcp.tool()
    async def ctf_ultimate_solve(
        target: str,
        challenge_type: str = "auto",
        time_limit: int = 1800,
        aggressive: bool = True
    ) -> Dict[str, Any]:
        """
        CTF终极求解器 - 解不出的题，全世界也解不出

        集成所有CTF解题技术:
        - Web: SQL注入、XSS、文件包含、命令注入、反序列化等
        - PWN: 栈溢出、堆利用、ROP链、格式化字符串等
        - Crypto: 经典密码、现代密码、RSA攻击等
        - Misc: 隐写术、取证、编码、流量分析等
        - Reverse: 静态分析、动态调试、反混淆等

        Args:
            target: CTF题目URL或文件路径
            challenge_type: 题目类型 (auto, web, pwn, crypto, misc, reverse)
            time_limit: 时间限制(秒)，默认30分钟
            aggressive: 是否启用激进模式

        Returns:
            解题结果，包含Flag和解题步骤
        """
        if not ULTIMATE_ENGINE_AVAILABLE:
            return {"error": "CTF求解器不可用"}

        solver = CTFUltimateSolver()
        result = await solver.solve_challenge(
            target=target,
            challenge_type=challenge_type,
            time_limit=time_limit,
            aggressive=aggressive
        )

        return result

    # ==================== 智能编排工具 ====================

    @mcp.tool()
    async def auto_pilot_attack(
        target: str,
        objective: str = "full_compromise",
        max_depth: int = 5,
        enable_exploitation: bool = False
    ) -> Dict[str, Any]:
        """
        自动驾驶攻击模式 - 基于结果自动选择下一步工具

        完全自动化的渗透测试:
        1. 自动识别目标类型
        2. 根据扫描结果自动选择合适的工具
        3. 发现漏洞后自动尝试利用
        4. 获取访问后自动进行横向移动
        5. 持续攻击直到达成目标

        Args:
            target: 目标URL、IP或网络范围
            objective: 攻击目标 (reconnaissance, initial_access, full_compromise, data_exfiltration)
            max_depth: 最大攻击深度
            enable_exploitation: 是否启用自动漏洞利用

        Returns:
            攻击结果，包含完整的攻击路径和发现
        """
        if not ORCHESTRATOR_AVAILABLE:
            return {"error": "工具编排器不可用"}

        orchestrator = get_tool_orchestrator()
        autopilot = AutoPilotAttack(orchestrator)

        result = await autopilot.run(
            target=target,
            objective=objective,
            max_depth=max_depth,
            enable_exploitation=enable_exploitation
        )

        return result

    @mcp.tool()
    async def smart_tool_chain(
        target: str,
        initial_tool: str,
        max_chain_length: int = 10
    ) -> Dict[str, Any]:
        """
        智能工具链 - 根据工具输出自动触发后续工具

        基于结果模式匹配自动选择工具:
        - 发现80端口  自动Web扫描
        - 发现SQL注入  自动sqlmap
        - 发现上传功能  自动尝试上传绕过
        - 发现CMS  自动CMS特定扫描

        Args:
            target: 目标
            initial_tool: 初始工具名称
            max_chain_length: 最大工具链长度

        Returns:
            工具链执行结果
        """
        if not ORCHESTRATOR_AVAILABLE:
            return {"error": "工具编排器不可用"}

        orchestrator = get_tool_orchestrator()
        result = await orchestrator.execute_smart_chain(
            target=target,
            initial_tool=initial_tool,
            max_chain_length=max_chain_length
        )

        return result

    # ==================== 智能缓存工具 ====================

    @mcp.tool()
    async def smart_scan(
        target: str,
        tools: List[str],
        use_cache: bool = True,
        cache_ttl: int = 3600
    ) -> Dict[str, Any]:
        """
        智能扫描 - 自动去重和缓存，避免重复扫描

        功能:
        - 自动检测等价扫描并跳过
        - 缓存扫描结果，相同参数直接返回
        - 智能合并多个工具的扫描结果
        - 增量扫描，只扫描新发现的目标

        Args:
            target: 目标
            tools: 要执行的工具列表
            use_cache: 是否使用缓存
            cache_ttl: 缓存有效期(秒)

        Returns:
            扫描结果(可能来自缓存)
        """
        if not OPTIMIZER_AVAILABLE:
            return {"error": "扫描优化器不可用"}

        optimizer = get_scan_optimizer()
        result = await optimizer.smart_scan(
            target=target,
            tools=tools,
            use_cache=use_cache,
            cache_ttl=cache_ttl
        )

        return result

    @mcp.tool()
    async def get_cached_results(target: str) -> Dict[str, Any]:
        """
        获取目标的缓存扫描结果

        Args:
            target: 目标URL或IP

        Returns:
            缓存的扫描结果
        """
        if not OPTIMIZER_AVAILABLE:
            return {"error": "扫描优化器不可用"}

        optimizer = get_scan_optimizer()
        return optimizer.get_cached_results(target)

    # ==================== AD攻击工具 ====================

    @mcp.tool()
    async def ad_full_attack(
        target_dc: str,
        domain: str,
        username: str = "",
        password: str = "",
        attack_mode: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Active Directory全面攻击

        包含攻击技术:
        - 信息枚举: 用户、组、GPO、ACL
        - Kerberos攻击: Kerberoasting、AS-REP Roasting
        - 凭据提取: DCSync、LSA Secrets、NTDS.dit
        - 横向移动: Pass-the-Hash、Pass-the-Ticket、DCOM
        - 持久化: Golden Ticket、Silver Ticket、AdminSDHolder

        Args:
            target_dc: 域控制器IP或主机名
            domain: 域名 (如 corp.local)
            username: 用户名(可选，用于认证攻击)
            password: 密码(可选)
            attack_mode: 攻击模式 (enum_only, kerberos, full, comprehensive)

        Returns:
            攻击结果，包含提取的凭据和攻击路径
        """
        if not AD_TOOLS_AVAILABLE:
            return {"error": "AD攻击工具不可用", "suggestion": "请确保Impacket等工具已安装"}

        orchestrator = get_ad_orchestrator()
        result = await orchestrator.full_ad_attack(
            target_dc=target_dc,
            domain=domain,
            username=username,
            password=password,
            attack_mode=attack_mode
        )

        return result

    @mcp.tool()
    async def kerberoast(
        target_dc: str,
        domain: str,
        username: str = "",
        password: str = "",
        output_format: str = "hashcat"
    ) -> Dict[str, Any]:
        """
        Kerberoasting攻击 - 提取服务账户TGS票据

        Args:
            target_dc: 域控制器
            domain: 域名
            username: 用户名
            password: 密码
            output_format: 输出格式 (hashcat, john)

        Returns:
            提取的TGS哈希，可用于离线破解
        """
        if not AD_TOOLS_AVAILABLE:
            return {"error": "AD攻击工具不可用"}

        orchestrator = get_ad_orchestrator()
        return await orchestrator.kerberoast(
            target_dc=target_dc,
            domain=domain,
            username=username,
            password=password,
            output_format=output_format
        )

    @mcp.tool()
    async def dcsync_attack(
        target_dc: str,
        domain: str,
        username: str,
        password: str,
        target_user: str = "Administrator"
    ) -> Dict[str, Any]:
        """
        DCSync攻击 - 模拟域控制器复制获取密码哈希

        需要: 域管理员权限或特定复制权限

        Args:
            target_dc: 域控制器
            domain: 域名
            username: 用户名(需要DCSync权限)
            password: 密码
            target_user: 要提取哈希的目标用户

        Returns:
            目标用户的NTLM哈希
        """
        if not AD_TOOLS_AVAILABLE:
            return {"error": "AD攻击工具不可用"}

        orchestrator = get_ad_orchestrator()
        return await orchestrator.dcsync(
            target_dc=target_dc,
            domain=domain,
            username=username,
            password=password,
            target_user=target_user
        )

    # ==================== 取证与隐写术工具 ====================

    @mcp.tool()
    async def forensics_full_analysis(
        target_path: str,
        analysis_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        全面取证分析

        支持分析类型:
        - 文件系统取证: 隐藏文件、删除恢复、时间线分析
        - 内存取证: 进程、网络连接、恶意代码
        - 网络取证: pcap分析、协议解析、数据提取
        - 隐写术检测: 图片、音频、文档隐写

        Args:
            target_path: 目标文件或目录路径
            analysis_type: 分析类型 (auto, file, memory, network, steganography)

        Returns:
            取证分析结果
        """
        if not FORENSICS_TOOLS_AVAILABLE:
            return {"error": "取证工具不可用"}

        orchestrator = get_forensics_orchestrator()
        return await orchestrator.full_analysis(
            target_path=target_path,
            analysis_type=analysis_type
        )

    @mcp.tool()
    async def stego_detect(
        file_path: str,
        extract_data: bool = True,
        password: str = ""
    ) -> Dict[str, Any]:
        """
        隐写术检测与提取

        支持格式:
        - 图片: PNG (zsteg), JPEG (steghide), BMP, GIF
        - 音频: WAV, MP3
        - 文档: PDF, DOCX
        - 压缩: ZIP (隐藏文件)

        Args:
            file_path: 文件路径
            extract_data: 是否尝试提取隐藏数据
            password: 密码(如果需要)

        Returns:
            检测和提取结果
        """
        if not FORENSICS_TOOLS_AVAILABLE:
            return {"error": "取证工具不可用"}

        orchestrator = get_forensics_orchestrator()
        return await orchestrator.detect_steganography(
            file_path=file_path,
            extract_data=extract_data,
            password=password
        )

    @mcp.tool()
    async def memory_forensics(
        dump_path: str,
        profile: str = "auto"
    ) -> Dict[str, Any]:
        """
        内存取证分析

        使用Volatility分析:
        - 进程列表和隐藏进程
        - 网络连接
        - 注册表
        - 密码和凭据
        - 恶意代码检测

        Args:
            dump_path: 内存转储文件路径
            profile: Volatility配置文件 (auto自动检测)

        Returns:
            内存分析结果
        """
        if not FORENSICS_TOOLS_AVAILABLE:
            return {"error": "取证工具不可用"}

        orchestrator = get_forensics_orchestrator()
        return await orchestrator.analyze_memory(
            dump_path=dump_path,
            profile=profile
        )

    @mcp.tool()
    async def ctf_misc_solve(
        file_path: str,
        hints: List[str] = None
    ) -> Dict[str, Any]:
        """
        CTF Misc题目自动求解

        自动尝试:
        - 文件类型识别和修复
        - 隐写术检测和提取
        - 编码识别和解码
        - 压缩包分析和密码破解
        - 流量包分析

        Args:
            file_path: 题目文件路径
            hints: 题目提示列表

        Returns:
            解题结果和Flag
        """
        if not FORENSICS_TOOLS_AVAILABLE:
            return {"error": "取证工具不可用"}

        solver = CTFMiscSolver()
        return await solver.solve(
            file_path=file_path,
            hints=hints or []
        )

    # ==================== 移动安全工具 ====================

    @mcp.tool()
    async def mobile_security_scan(
        app_path: str,
        platform: str = "auto"
    ) -> Dict[str, Any]:
        """
        移动应用安全扫描

        分析内容:
        - APK/IPA结构分析
        - 权限和组件分析
        - 硬编码密钥和凭据
        - 加密和混淆检测
        - 已知漏洞匹配
        - 动态分析(如Frida可用)

        Args:
            app_path: APK或IPA文件路径
            platform: 平台 (auto, android, ios)

        Returns:
            安全扫描结果
        """
        if not MOBILE_TOOLS_AVAILABLE:
            return {"error": "移动安全工具不可用"}

        scanner = get_mobile_scanner()
        return await scanner.full_scan(
            app_path=app_path,
            platform=platform
        )

    @mcp.tool()
    async def apk_decompile(
        apk_path: str,
        output_dir: str = ""
    ) -> Dict[str, Any]:
        """
        APK反编译分析

        使用工具:
        - apktool: 资源和manifest提取
        - jadx: Java源码反编译
        - dex2jar: DEX转JAR

        Args:
            apk_path: APK文件路径
            output_dir: 输出目录(默认自动生成)

        Returns:
            反编译结果和发现的敏感信息
        """
        if not MOBILE_TOOLS_AVAILABLE:
            return {"error": "移动安全工具不可用"}

        scanner = get_mobile_scanner()
        return await scanner.decompile_apk(
            apk_path=apk_path,
            output_dir=output_dir
        )

    @mcp.tool()
    async def frida_hook(
        target: str,
        script: str = "",
        hook_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        Frida动态Hook

        支持Hook:
        - SSL Pinning绕过
        - Root/越狱检测绕过
        - 加密函数Hook
        - API调用监控
        - 自定义脚本执行

        Args:
            target: 目标应用包名或进程
            script: 自定义Frida脚本(可选)
            hook_type: Hook类型 (auto, ssl_bypass, root_bypass, crypto, custom)

        Returns:
            Hook执行结果
        """
        if not MOBILE_TOOLS_AVAILABLE:
            return {"error": "移动安全工具不可用"}

        scanner = get_mobile_scanner()
        return await scanner.frida_hook(
            target=target,
            script=script,
            hook_type=hook_type
        )

    # ==================== CTF工具 (v2.2 - ) ====================

    @mcp.tool()
    async def ctf_poc_scan(
        target: str,
        poc_category: str = "all",
        max_workers: int = 5,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        CTF POC扫描引擎 - 使用YAML定义的POC进行漏洞扫描

        POC 扫描系统，支持：
        - 多步骤POC执行
        - 条件匹配和数据提取
        - 自动Flag检测
        - 并发扫描优化

        Args:
            target: 目标URL
            poc_category: POC类别 (all, web, cve, rce, sqli, xss, lfi, ssrf)
            max_workers: 最大并发数
            timeout: 单个POC超时时间(秒)

        Returns:
            扫描结果，包含发现的漏洞和提取的数据
        """
        if not CTF_POC_ENGINE_AVAILABLE:
            return {"error": "CTF POC引擎不可用", "suggestion": "请检查 ctf_poc_engine.py 是否正确安装"}

        manager = get_ctf_poc_manager()

        # 创建扫描器
        scanner = POCScanner(max_workers=max_workers, timeout=timeout)

        # 获取指定类别的POC
        pocs = []
        if poc_category == "all":
            pocs = manager.get_all_pocs()
        else:
            pocs = manager.get_pocs_by_category(poc_category)

        # 执行扫描
        results = await scanner.scan(target, pocs=pocs)

        return {
            "target": target,
            "poc_category": poc_category,
            "total_pocs": len(pocs),
            "vulnerabilities_found": len([r for r in results if r.success]),
            "results": [
                {
                    "poc_name": r.poc_name,
                    "vulnerable": r.success,
                    "severity": r.severity,
                    "extracted_data": r.extracted_data,
                    "details": r.details
                }
                for r in results
            ],
            "flags_detected": [r.extracted_data.get("flag") for r in results if r.extracted_data.get("flag")]
        }

    @mcp.tool()
    async def ctf_multi_agent_solve(
        target: str,
        task_id: str = "",
        timeout: int = 300,
        aggressive: bool = False
    ) -> Dict[str, Any]:
        """
        CTF多Agent协作求解器 - 智能化CTF题目自动解题

        基于CTF 求解的多Agent架构：
        - Explorer Agent: 页面探索，发现新路径和API
        - Scanner Agent: 漏洞扫描，识别安全问题
        - Solutioner Agent: 方案生成，制定攻击策略
        - Executor Agent: 攻击执行，获取Flag

        Args:
            target: CTF题目URL
            task_id: 任务ID（可选）
            timeout: 总超时时间(秒)
            aggressive: 是否启用激进模式

        Returns:
            解题结果，包含发现的Flag和攻击路径
        """
        if not CTF_AGENT_FRAMEWORK_AVAILABLE:
            return {"error": "CTF Agent框架不可用", "suggestion": "请检查 ctf_agent_framework.py 是否正确安装"}

        coordinator = get_ctf_coordinator()

        result = await coordinator.solve(
            target_url=target,
            task_id=task_id or f"ctf_{int(__import__('time').time())}",
            timeout=timeout,
            aggressive=aggressive
        )

        return result

    @mcp.tool()
    async def ctf_knowledge_detect(
        target: str,
        vuln_types: str = "all"
    ) -> Dict[str, Any]:
        """
        知识库驱动的漏洞检测 - 使用预定义的Payload和检测方法

        基于CTF 求解的知识库系统：
        - 内置多种漏洞类型的Payload模板
        - 智能检测方法匹配
        - Flag获取策略推荐

        Args:
            target: 目标URL
            vuln_types: 要检测的漏洞类型 (all, sqli, xss, lfi, cmdi, ssti, ssrf, idor, jwt)

        Returns:
            检测结果，包含发现的漏洞和利用建议
        """
        if not CTF_KNOWLEDGE_BASE_AVAILABLE:
            return {"error": "CTF知识库不可用", "suggestion": "请检查 ctf_knowledge_base.py 是否正确安装"}

        kb = get_ctf_knowledge_base()
        detector = KnowledgeDrivenDetector(kb)

        # 解析漏洞类型
        types_to_detect = []
        if vuln_types == "all":
            types_to_detect = kb.get_all_vuln_types()
        else:
            types_to_detect = [t.strip() for t in vuln_types.split(",")]

        # 执行检测
        results = await detector.detect_all(target)

        # 获取Flag提取建议
        flag_getters = {}
        for vuln in results.get("vulnerabilities", []):
            getters = kb.get_flag_getters(vuln["type"])
            if getters:
                flag_getters[vuln["type"]] = [
                    {"name": g.name, "commands": g.commands, "description": g.description}
                    for g in getters[:3]  # 每种漏洞最多3个建议
                ]

        return {
            "target": target,
            "vuln_types_checked": types_to_detect,
            "vulnerabilities": results.get("vulnerabilities", []),
            "total_found": results.get("total", 0),
            "flag_extraction_suggestions": flag_getters
        }

    @mcp.tool()
    async def ctf_get_payloads(
        vuln_type: str,
        bypass_type: str = "none",
        limit: int = 20
    ) -> Dict[str, Any]:
        """
        获取漏洞Payload模板 - 从知识库中获取指定漏洞类型的Payload

        支持的漏洞类型:
        - sqli: SQL注入
        - xss: 跨站脚本
        - lfi: 本地文件包含
        - cmdi: 命令注入
        - ssti: 服务端模板注入
        - ssrf: 服务端请求伪造
        - idor: 不安全直接对象引用
        - jwt: JWT令牌漏洞

        Args:
            vuln_type: 漏洞类型
            bypass_type: 绕过类型 (none, waf, encoding, case)
            limit: 返回数量限制

        Returns:
            Payload列表和使用说明
        """
        if not CTF_KNOWLEDGE_BASE_AVAILABLE:
            return {"error": "CTF知识库不可用"}

        kb = get_ctf_knowledge_base()
        payloads = kb.get_payloads(vuln_type, bypass_type)[:limit]

        return {
            "vuln_type": vuln_type,
            "bypass_type": bypass_type,
            "total": len(payloads),
            "payloads": [
                {
                    "name": p.name,
                    "payload": p.payload,
                    "description": p.description,
                    "bypass_type": p.bypass_type,
                    "success_indicators": p.success_indicators
                }
                for p in payloads
            ]
        }

    @mcp.tool()
    async def ctf_detect_flags(content: str) -> Dict[str, Any]:
        """
        检测内容中的Flag - 使用多种模式匹配Flag格式

        支持的Flag格式:
        - flag{...}
        - FLAG{...}
        - ctf{...}
        - CTF{...}
        - DASCTF{...}
        - MD5哈希 (32字符)
        - SHA1哈希 (40字符)
        - SHA256哈希 (64字符)

        Args:
            content: 要检测的内容

        Returns:
            检测到的Flag列表
        """
        if not CTF_KNOWLEDGE_BASE_AVAILABLE:
            return {"error": "CTF知识库不可用"}

        kb = get_ctf_knowledge_base()
        flags = kb.detect_flags(content)

        return {
            "flags_found": len(flags),
            "flags": flags,
            "content_length": len(content)
        }

    @mcp.tool()
    async def ctf_suggest_action(
        vuln_type: str,
        phase: str,
        context: str = "{}"
    ) -> Dict[str, Any]:
        """
        智能动作建议 - 基于当前阶段和上下文推荐下一步

        阶段说明:
        - detection: 漏洞检测阶段
        - exploitation: 漏洞利用阶段
        - flag_extraction: Flag提取阶段

        Args:
            vuln_type: 漏洞类型
            phase: 当前阶段 (detection, exploitation, flag_extraction)
            context: JSON格式的上下文信息

        Returns:
            推荐的下一步动作
        """
        if not CTF_KNOWLEDGE_BASE_AVAILABLE:
            return {"error": "CTF知识库不可用"}

        import json
        try:
            ctx = json.loads(context)
        except:
            ctx = {}

        kb = get_ctf_knowledge_base()
        suggestion = kb.suggest_next_action(vuln_type, phase, ctx)

        return {
            "vuln_type": vuln_type,
            "current_phase": phase,
            "suggestion": suggestion
        }

    # ==================== 系统状态工具 ====================

    @mcp.tool()
    async def v2_system_status() -> Dict[str, Any]:
        """
        获取Kali MCP v2.0系统状态

        Returns:
            各模块可用性和统计信息
        """
        status = {
            "version": "2.2.0",
            "modules": {
                "ultimate_engine": {
                    "available": ULTIMATE_ENGINE_AVAILABLE,
                    "description": "终极扫描引擎 - 100%工具覆盖"
                },
                "tool_orchestrator": {
                    "available": ORCHESTRATOR_AVAILABLE,
                    "description": "智能工具编排 - 结果驱动执行"
                },
                "scan_optimizer": {
                    "available": OPTIMIZER_AVAILABLE,
                    "description": "智能缓存和去重 - 避免重复扫描"
                },
                "skill_dispatcher": {
                    "available": SKILL_DISPATCHER_AVAILABLE,
                    "description": "Skill知识库集成"
                },
                "ad_tools": {
                    "available": AD_TOOLS_AVAILABLE,
                    "description": "AD攻击工具包"
                },
                "forensics_tools": {
                    "available": FORENSICS_TOOLS_AVAILABLE,
                    "description": "取证与隐写术工具"
                },
                "mobile_tools": {
                    "available": MOBILE_TOOLS_AVAILABLE,
                    "description": "移动安全工具"
                },
                # CTF模块 (v2.2)
                "ctf_poc_engine": {
                    "available": CTF_POC_ENGINE_AVAILABLE,
                    "description": "CTF POC扫描引擎 - YAML POC定义"
                },
                "ctf_agent_framework": {
                    "available": CTF_AGENT_FRAMEWORK_AVAILABLE,
                    "description": "CTF多Agent框架 - 智能协作解题"
                },
                "ctf_knowledge_base": {
                    "available": CTF_KNOWLEDGE_BASE_AVAILABLE,
                    "description": "CTF知识库 - Payload和检测方法"
                }
            },
            "capabilities": {
                "total_tools": 199,  # 193 + 6 新CTF工具
                "new_tools_v2": 31,  # 25 + 6 新CTF工具
                "vulnerability_coverage": "100% OWASP Top 10, 100% SANS Top 25",
                "target_types": ["web", "network", "api", "database", "mobile", "iot", "ad"],
                "iteration_levels": ["quick", "standard", "thorough", "exhaustive"],
                "ctf_features": ["poc_scan", "multi_agent", "knowledge_detect", "payloads", "flag_detect", "action_suggest"]
            }
        }

        # 统计可用模块数
        available_count = sum(1 for m in status["modules"].values() if m["available"])
        status["summary"] = f"{available_count}/{len(status['modules'])} 模块可用"

        return status

    logger.info(" Kali MCP v2.0 工具已注册完成")
    return True


# 工具数量统计
V2_TOOL_COUNT = 31  # 新增工具数量 (25 v2.0 + 6 v2.2 CTF工具)
