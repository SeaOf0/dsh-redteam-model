#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
取证与隐写术工具包

用于:
1. 数字取证 - 内存分析、磁盘分析、日志分析
2. 隐写术检测 - 图片、音频、视频隐写
3. 文件分析 - 元数据提取、格式识别
4. CTF Misc题目求解

常用于CTF竞赛和安全取证调查
"""

import subprocess
import os
import re
import json
import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FileInfo:
    """文件信息"""
    path: str
    size: int
    md5: str
    sha256: str
    file_type: str
    magic_bytes: bytes


class FileAnalyzer:
    """文件分析工具"""

    @staticmethod
    def run_command(cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
        """执行命令"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_file_info(file_path: str) -> FileInfo:
        """获取文件基本信息"""
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")

        # 计算哈希
        with open(file_path, "rb") as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            magic_bytes = data[:16]

        # 获取文件类型
        result = subprocess.run(["file", file_path], capture_output=True, text=True)
        file_type = result.stdout.split(": ", 1)[-1].strip() if result.returncode == 0 else "Unknown"

        return FileInfo(
            path=str(path.absolute()),
            size=path.stat().st_size,
            md5=md5,
            sha256=sha256,
            file_type=file_type,
            magic_bytes=magic_bytes,
        )

    def binwalk_analyze(self, file_path: str, extract: bool = False) -> Dict[str, Any]:
        """
        使用binwalk分析文件

        检测嵌入的文件和数据
        """
        results = {"signatures": [], "extracted_files": [], "tool_output": {}}

        cmd = ["binwalk"]
        if extract:
            cmd.append("-e")
        cmd.append(file_path)

        output = self.run_command(cmd)
        results["tool_output"]["binwalk"] = output

        if output["success"]:
            # 解析签名
            for line in output["stdout"].split("\n"):
                if line.strip() and not line.startswith("DECIMAL"):
                    parts = line.split()
                    if len(parts) >= 3:
                        results["signatures"].append({
                            "offset": parts[0],
                            "type": " ".join(parts[2:]),
                        })

        # 查找提取的文件
        if extract:
            extract_dir = f"_{Path(file_path).name}.extracted"
            if os.path.exists(extract_dir):
                for root, dirs, files in os.walk(extract_dir):
                    for f in files:
                        results["extracted_files"].append(os.path.join(root, f))

        return results

    def exiftool_analyze(self, file_path: str) -> Dict[str, Any]:
        """
        使用exiftool提取元数据

        常用于发现隐藏信息
        """
        results = {"metadata": {}, "tool_output": {}}

        cmd = ["exiftool", "-json", file_path]
        output = self.run_command(cmd)
        results["tool_output"]["exiftool"] = output

        if output["success"]:
            try:
                metadata = json.loads(output["stdout"])
                if metadata:
                    results["metadata"] = metadata[0]
            except json.JSONDecodeError:
                results["metadata_raw"] = output["stdout"]

        return results

    def strings_analyze(self, file_path: str, min_length: int = 4,
                       encoding: str = "s") -> Dict[str, Any]:
        """
        提取文件中的字符串

        encoding: s=7-bit, S=8-bit, b=16-bit BE, l=16-bit LE, B=32-bit BE, L=32-bit LE
        """
        results = {"strings": [], "flags": [], "urls": [], "emails": []}

        cmd = ["strings", f"-n{min_length}", f"-e{encoding}", file_path]
        output = self.run_command(cmd)

        if output["success"]:
            strings = output["stdout"].split("\n")
            results["strings"] = strings[:1000]  # 限制数量
            results["total_count"] = len(strings)

            # 查找flag
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}',
            ]
            for pattern in flag_patterns:
                matches = re.findall(pattern, output["stdout"], re.IGNORECASE)
                results["flags"].extend(matches)

            # 查找URL
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            results["urls"] = re.findall(url_pattern, output["stdout"])

            # 查找邮箱
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            results["emails"] = re.findall(email_pattern, output["stdout"])

        return results

    def foremost_carve(self, file_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        使用foremost进行文件雕刻

        从原始数据中恢复文件
        """
        results = {"carved_files": [], "tool_output": {}}

        output_dir = output_dir or f"/tmp/foremost_{os.path.basename(file_path)}"

        cmd = ["foremost", "-i", file_path, "-o", output_dir]
        output = self.run_command(cmd, timeout=300)
        results["tool_output"]["foremost"] = output

        # 查找恢复的文件
        if os.path.exists(output_dir):
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    if f != "audit.txt":
                        results["carved_files"].append(os.path.join(root, f))

        return results


class SteganographyDetector:
    """隐写术检测工具"""

    def __init__(self):
        self.analyzer = FileAnalyzer()

    def steghide_detect(self, file_path: str, password: str = "") -> Dict[str, Any]:
        """
        使用steghide检测和提取隐藏数据

        支持JPEG和BMP格式
        """
        results = {"has_hidden_data": False, "extracted_data": None, "tool_output": {}}

        # 尝试提取
        cmd = ["steghide", "extract", "-sf", file_path, "-p", password, "-f"]
        output = self.analyzer.run_command(cmd)
        results["tool_output"]["steghide"] = output

        if output["success"] and "wrote extracted data" in output["stdout"].lower():
            results["has_hidden_data"] = True
            # 查找提取的文件
            for line in output["stdout"].split("\n"):
                if "wrote extracted data to" in line.lower():
                    filename = line.split('"')[-2] if '"' in line else None
                    if filename and os.path.exists(filename):
                        with open(filename, "rb") as f:
                            results["extracted_data"] = f.read()

        return results

    def steghide_bruteforce(self, file_path: str,
                           wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        """
        暴力破解steghide密码
        """
        results = {"password_found": None, "attempts": 0}

        if not os.path.exists(wordlist):
            return {"error": f"字典不存在: {wordlist}"}

        with open(wordlist, "r", errors="ignore") as f:
            for line in f:
                password = line.strip()
                results["attempts"] += 1

                if results["attempts"] > 10000:  # 限制尝试次数
                    break

                cmd = ["steghide", "extract", "-sf", file_path, "-p", password, "-f"]
                output = subprocess.run(cmd, capture_output=True, text=True)

                if output.returncode == 0:
                    results["password_found"] = password
                    break

        return results

    def zsteg_detect(self, file_path: str) -> Dict[str, Any]:
        """
        使用zsteg检测PNG/BMP隐写

        检测LSB隐写等技术
        """
        results = {"findings": [], "tool_output": {}}

        cmd = ["zsteg", "-a", file_path]
        output = self.analyzer.run_command(cmd)
        results["tool_output"]["zsteg"] = output

        if output["success"]:
            for line in output["stdout"].split("\n"):
                if line.strip() and not line.startswith("imagedata"):
                    results["findings"].append(line)

                    # 检查是否包含flag
                    if re.search(r'flag\{|ctf\{', line, re.IGNORECASE):
                        results["flag_found"] = line

        return results

    def stegsolve_analyze(self, file_path: str) -> Dict[str, Any]:
        """
        模拟stegsolve分析

        分析不同颜色通道和位平面
        """
        results = {"analysis": [], "tool_output": {}}

        try:
            from PIL import Image
            import numpy as np

            img = Image.open(file_path)
            img_array = np.array(img)

            # 分析RGB通道
            if len(img_array.shape) >= 3:
                for i, channel in enumerate(["Red", "Green", "Blue"]):
                    if i < img_array.shape[2]:
                        channel_data = img_array[:, :, i]

                        # 检查LSB
                        lsb = channel_data & 1
                        lsb_bytes = np.packbits(lsb.flatten())

                        # 尝试解码为字符串
                        try:
                            text = lsb_bytes.tobytes().decode('utf-8', errors='ignore')
                            if re.search(r'flag\{|ctf\{', text, re.IGNORECASE):
                                results["analysis"].append({
                                    "channel": channel,
                                    "method": "LSB",
                                    "finding": text[:500],
                                })
                        except:
                            pass

            results["image_info"] = {
                "size": img.size,
                "mode": img.mode,
                "format": img.format,
            }

        except ImportError:
            results["error"] = "需要安装PIL: pip install Pillow"
        except Exception as e:
            results["error"] = str(e)

        return results

    def audio_steg_detect(self, file_path: str) -> Dict[str, Any]:
        """
        检测音频隐写

        包括频谱分析、LSB隐写等
        """
        results = {"findings": [], "tool_output": {}}

        # 使用sonic-visualiser或spectro进行频谱分析
        # 这里使用ffmpeg提取音频数据

        # 1. 检查音频元数据
        cmd = ["ffprobe", "-v", "quiet", "-print_format", "json",
               "-show_format", "-show_streams", file_path]
        output = self.analyzer.run_command(cmd)
        results["tool_output"]["ffprobe"] = output

        if output["success"]:
            try:
                info = json.loads(output["stdout"])
                results["audio_info"] = info
            except:
                pass

        # 2. 导出原始数据进行分析
        raw_output = f"/tmp/{os.path.basename(file_path)}.raw"
        cmd2 = ["ffmpeg", "-y", "-i", file_path, "-f", "s16le",
                "-acodec", "pcm_s16le", raw_output]
        self.analyzer.run_command(cmd2)

        if os.path.exists(raw_output):
            # 分析原始数据
            strings_result = self.analyzer.strings_analyze(raw_output)
            if strings_result.get("flags"):
                results["findings"].extend(strings_result["flags"])

        return results

    def detect(self, file_path: str, extract: bool = True, password: str = "") -> Dict[str, Any]:
        """
        统一的隐写检测接口

        根据文件类型自动选择合适的检测方法

        Args:
            file_path: 文件路径
            extract: 是否尝试提取隐藏数据
            password: 密码(如果需要)

        Returns:
            检测和提取结果
        """
        results = {
            "file_path": file_path,
            "file_type": None,
            "has_hidden_data": False,
            "findings": [],
            "extracted_data": None,
            "methods_used": []
        }

        if not os.path.exists(file_path):
            results["error"] = f"文件不存在: {file_path}"
            return results

        # 确定文件类型
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        results["file_type"] = mime_type or ext

        # 根据文件类型选择检测方法
        try:
            # PNG/BMP - 使用zsteg
            if ext in ['.png', '.bmp'] or (mime_type and 'png' in mime_type):
                results["methods_used"].append("zsteg")
                zsteg_result = self.zsteg_detect(file_path)
                if zsteg_result.get("findings"):
                    results["findings"].extend(zsteg_result["findings"])
                    results["has_hidden_data"] = True
                if zsteg_result.get("flag_found"):
                    results["extracted_data"] = zsteg_result["flag_found"]

            # JPEG/BMP - 使用steghide
            if ext in ['.jpg', '.jpeg', '.bmp'] or (mime_type and ('jpeg' in mime_type or 'bmp' in mime_type)):
                results["methods_used"].append("steghide")
                steghide_result = self.steghide_detect(file_path, password)
                if steghide_result.get("has_hidden_data"):
                    results["has_hidden_data"] = True
                    if steghide_result.get("extracted_data"):
                        results["extracted_data"] = steghide_result["extracted_data"]

            # 图片 - 使用stegsolve分析
            if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif'] or (mime_type and 'image' in mime_type):
                results["methods_used"].append("stegsolve")
                stegsolve_result = self.stegsolve_analyze(file_path)
                if stegsolve_result.get("analysis"):
                    results["findings"].extend([a.get("finding", "") for a in stegsolve_result["analysis"]])
                    results["has_hidden_data"] = True
                results["image_info"] = stegsolve_result.get("image_info")

            # 音频文件
            if ext in ['.wav', '.mp3', '.flac', '.ogg'] or (mime_type and 'audio' in mime_type):
                results["methods_used"].append("audio_steg")
                audio_result = self.audio_steg_detect(file_path)
                if audio_result.get("findings"):
                    results["findings"].extend(audio_result["findings"])
                    results["has_hidden_data"] = True
                results["audio_info"] = audio_result.get("audio_info")

            # 如果没有找到数据且指定了密码，尝试暴力破解
            if not results["has_hidden_data"] and extract and not password:
                if ext in ['.jpg', '.jpeg', '.bmp']:
                    results["methods_used"].append("steghide_bruteforce")
                    bf_result = self.steghide_bruteforce(file_path)
                    if bf_result.get("password_found"):
                        results["password_found"] = bf_result["password_found"]
                        # 使用找到的密码重新提取
                        steghide_result = self.steghide_detect(file_path, bf_result["password_found"])
                        if steghide_result.get("extracted_data"):
                            results["extracted_data"] = steghide_result["extracted_data"]
                            results["has_hidden_data"] = True

        except Exception as e:
            results["error"] = str(e)

        return results


class MemoryForensics:
    """内存取证工具"""

    def __init__(self):
        self.analyzer = FileAnalyzer()

    def volatility_analyze(self, memory_dump: str, profile: str = None) -> Dict[str, Any]:
        """
        使用Volatility分析内存镜像

        自动识别profile并提取关键信息
        """
        results = {"profile": None, "findings": {}, "tool_output": {}}

        # 1. 识别profile
        if not profile:
            cmd = ["vol.py", "-f", memory_dump, "imageinfo"]
            output = self.analyzer.run_command(cmd, timeout=300)
            results["tool_output"]["imageinfo"] = output

            if output["success"]:
                # 提取建议的profile
                for line in output["stdout"].split("\n"):
                    if "Suggested Profile" in line:
                        profiles = line.split(":")[1].strip().split(",")
                        profile = profiles[0].strip()
                        break

        if not profile:
            profile = "Win7SP1x64"  # 默认

        results["profile"] = profile

        # 2. 提取关键信息
        plugins = [
            ("pslist", "进程列表"),
            ("pstree", "进程树"),
            ("cmdline", "命令行"),
            ("netscan", "网络连接"),
            ("filescan", "文件扫描"),
            ("hashdump", "密码哈希"),
        ]

        for plugin, description in plugins:
            cmd = ["vol.py", "-f", memory_dump, "--profile", profile, plugin]
            output = self.analyzer.run_command(cmd, timeout=300)
            results["findings"][plugin] = {
                "description": description,
                "output": output,
            }

        return results

    def extract_strings_from_memory(self, memory_dump: str) -> Dict[str, Any]:
        """从内存镜像提取字符串"""
        return self.analyzer.strings_analyze(memory_dump)


class NetworkForensics:
    """网络取证工具"""

    def __init__(self):
        self.analyzer = FileAnalyzer()

    def pcap_analyze(self, pcap_file: str) -> Dict[str, Any]:
        """
        分析PCAP文件

        提取HTTP请求、DNS查询、凭据等
        """
        results = {"statistics": {}, "findings": [], "tool_output": {}}

        # 1. 获取统计信息
        cmd = ["tshark", "-r", pcap_file, "-qz", "io,stat,1"]
        output = self.analyzer.run_command(cmd)
        results["tool_output"]["statistics"] = output

        # 2. 提取HTTP请求
        cmd2 = ["tshark", "-r", pcap_file, "-Y", "http.request",
                "-T", "fields", "-e", "http.host", "-e", "http.request.uri"]
        output2 = self.analyzer.run_command(cmd2)
        results["tool_output"]["http_requests"] = output2

        if output2["success"]:
            results["http_requests"] = output2["stdout"].split("\n")

        # 3. 提取DNS查询
        cmd3 = ["tshark", "-r", pcap_file, "-Y", "dns.qry.name",
                "-T", "fields", "-e", "dns.qry.name"]
        output3 = self.analyzer.run_command(cmd3)
        results["tool_output"]["dns_queries"] = output3

        if output3["success"]:
            results["dns_queries"] = list(set(output3["stdout"].split("\n")))

        # 4. 提取可能的凭据
        cmd4 = ["tshark", "-r", pcap_file, "-Y",
                "http.authbasic or ftp.request.command==PASS or smtp.req.command==AUTH"]
        output4 = self.analyzer.run_command(cmd4)
        results["tool_output"]["credentials"] = output4

        # 5. 导出HTTP对象
        export_dir = f"/tmp/pcap_export_{os.path.basename(pcap_file)}"
        os.makedirs(export_dir, exist_ok=True)
        cmd5 = ["tshark", "-r", pcap_file, "--export-objects",
                f"http,{export_dir}"]
        output5 = self.analyzer.run_command(cmd5)
        results["tool_output"]["export"] = output5

        # 列出导出的文件
        if os.path.exists(export_dir):
            results["exported_files"] = os.listdir(export_dir)

        return results

    def extract_files_from_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """
        从PCAP中提取文件

        使用NetworkMiner或tcpflow
        """
        results = {"files": [], "tool_output": {}}

        output_dir = f"/tmp/pcap_files_{os.path.basename(pcap_file)}"
        os.makedirs(output_dir, exist_ok=True)

        # 使用tcpflow
        cmd = ["tcpflow", "-r", pcap_file, "-o", output_dir]
        output = self.analyzer.run_command(cmd)
        results["tool_output"]["tcpflow"] = output

        if os.path.exists(output_dir):
            for f in os.listdir(output_dir):
                file_path = os.path.join(output_dir, f)
                if os.path.isfile(file_path):
                    results["files"].append({
                        "name": f,
                        "size": os.path.getsize(file_path),
                        "path": file_path,
                    })

        return results


class CTFMiscSolver:
    """
    CTF Misc题目求解器

    综合运用各种取证和隐写术技术
    """

    def __init__(self):
        self.file_analyzer = FileAnalyzer()
        self.steg_detector = SteganographyDetector()
        self.mem_forensics = MemoryForensics()
        self.net_forensics = NetworkForensics()

    def auto_solve(self, file_path: str) -> Dict[str, Any]:
        """
        自动分析文件并尝试找到flag

        根据文件类型选择合适的分析方法
        """
        results = {
            "file_info": None,
            "analysis_steps": [],
            "flags_found": [],
        }

        print(f"[*] CTF Misc求解器启动")
        print(f"[*] 文件: {file_path}")

        # 1. 获取文件信息
        try:
            file_info = self.file_analyzer.get_file_info(file_path)
            results["file_info"] = {
                "path": file_info.path,
                "size": file_info.size,
                "md5": file_info.md5,
                "type": file_info.file_type,
            }
            print(f"[*] 文件类型: {file_info.file_type}")
        except Exception as e:
            return {"error": str(e)}

        file_type = file_info.file_type.lower()

        # 2. 通用分析
        print("\n[*] 步骤1: 字符串提取")
        strings_result = self.file_analyzer.strings_analyze(file_path)
        results["analysis_steps"].append({"step": "strings", "result": strings_result})
        if strings_result.get("flags"):
            results["flags_found"].extend(strings_result["flags"])
            print(f"[+] 发现Flag: {strings_result['flags']}")

        print("\n[*] 步骤2: Binwalk分析")
        binwalk_result = self.file_analyzer.binwalk_analyze(file_path, extract=True)
        results["analysis_steps"].append({"step": "binwalk", "result": binwalk_result})

        # 3. 根据文件类型进行专项分析
        if "image" in file_type or file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            print("\n[*] 步骤3: 图片隐写分析")

            # Exiftool
            exif_result = self.file_analyzer.exiftool_analyze(file_path)
            results["analysis_steps"].append({"step": "exiftool", "result": exif_result})

            # 检查元数据中的flag
            metadata_str = json.dumps(exif_result.get("metadata", {}))
            flags = re.findall(r'flag\{[^}]+\}', metadata_str, re.IGNORECASE)
            if flags:
                results["flags_found"].extend(flags)

            # Zsteg (PNG/BMP)
            if file_path.lower().endswith(('.png', '.bmp')):
                zsteg_result = self.steg_detector.zsteg_detect(file_path)
                results["analysis_steps"].append({"step": "zsteg", "result": zsteg_result})
                if zsteg_result.get("flag_found"):
                    results["flags_found"].append(zsteg_result["flag_found"])

            # Steghide (JPEG/BMP)
            if file_path.lower().endswith(('.jpg', '.jpeg', '.bmp')):
                steg_result = self.steg_detector.steghide_detect(file_path)
                results["analysis_steps"].append({"step": "steghide", "result": steg_result})

                # 尝试常见密码
                common_passwords = ["", "password", "123456", "flag", "ctf"]
                for pwd in common_passwords:
                    steg_result = self.steg_detector.steghide_detect(file_path, pwd)
                    if steg_result.get("has_hidden_data"):
                        print(f"[+] Steghide密码: {pwd}")
                        break

        elif "audio" in file_type or file_path.lower().endswith(('.wav', '.mp3', '.flac')):
            print("\n[*] 步骤3: 音频隐写分析")
            audio_result = self.steg_detector.audio_steg_detect(file_path)
            results["analysis_steps"].append({"step": "audio_steg", "result": audio_result})

        elif "pcap" in file_type or file_path.lower().endswith(('.pcap', '.pcapng')):
            print("\n[*] 步骤3: 网络流量分析")
            pcap_result = self.net_forensics.pcap_analyze(file_path)
            results["analysis_steps"].append({"step": "pcap", "result": pcap_result})

        elif "zip" in file_type or "archive" in file_type:
            print("\n[*] 步骤3: 压缩包分析")
            # 尝试解压
            extract_dir = f"/tmp/extract_{os.path.basename(file_path)}"
            cmd = ["7z", "x", "-y", f"-o{extract_dir}", file_path]
            output = self.file_analyzer.run_command(cmd)
            results["analysis_steps"].append({"step": "extract", "result": output})

        # 4. 检查提取的文件
        if binwalk_result.get("extracted_files"):
            print(f"\n[*] 步骤4: 分析提取的{len(binwalk_result['extracted_files'])}个文件")
            for extracted_file in binwalk_result["extracted_files"][:10]:  # 限制数量
                sub_strings = self.file_analyzer.strings_analyze(extracted_file)
                if sub_strings.get("flags"):
                    results["flags_found"].extend(sub_strings["flags"])

        # 去重
        results["flags_found"] = list(set(results["flags_found"]))

        print(f"\n[+] 分析完成")
        print(f"    发现Flag数量: {len(results['flags_found'])}")

        return results


# 导出
__all__ = [
    "FileAnalyzer",
    "SteganographyDetector",
    "MemoryForensics",
    "NetworkForensics",
    "CTFMiscSolver",
    "FileInfo",
]
