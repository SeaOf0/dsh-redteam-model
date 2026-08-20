#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动应用安全分析工具包

用于Android和iOS应用安全测试:
1. APK/IPA静态分析 - 反编译、代码审计
2. 动态分析 - Hook、流量分析
3. 漏洞检测 - 硬编码凭据、不安全存储
4. 逆向工程 - 加固检测、脱壳

用于授权的移动应用安全评估
"""

import subprocess
import os
import re
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class APKInfo:
    """APK基本信息"""
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]


class APKAnalyzer:
    """Android APK分析工具"""

    @staticmethod
    def run_command(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
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

    def get_apk_info(self, apk_path: str) -> Dict[str, Any]:
        """
        获取APK基本信息

        使用aapt或apktool
        """
        results = {"info": {}, "tool_output": {}}

        # 使用aapt
        cmd = ["aapt", "dump", "badging", apk_path]
        output = self.run_command(cmd)
        results["tool_output"]["aapt"] = output

        if output["success"]:
            # 解析包名
            match = re.search(r"package: name='([^']+)'", output["stdout"])
            if match:
                results["info"]["package_name"] = match.group(1)

            # 解析版本
            match = re.search(r"versionName='([^']+)'", output["stdout"])
            if match:
                results["info"]["version_name"] = match.group(1)

            match = re.search(r"versionCode='([^']+)'", output["stdout"])
            if match:
                results["info"]["version_code"] = match.group(1)

            # 解析SDK版本
            match = re.search(r"sdkVersion:'([^']+)'", output["stdout"])
            if match:
                results["info"]["min_sdk"] = match.group(1)

            match = re.search(r"targetSdkVersion:'([^']+)'", output["stdout"])
            if match:
                results["info"]["target_sdk"] = match.group(1)

            # 解析权限
            permissions = re.findall(r"uses-permission: name='([^']+)'", output["stdout"])
            results["info"]["permissions"] = permissions

            # 解析Activity
            activities = re.findall(r"activity-alias: name='([^']+)'|launchable-activity: name='([^']+)'", output["stdout"])
            results["info"]["activities"] = [a[0] or a[1] for a in activities]

        return results

    def decompile_apk(self, apk_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        反编译APK

        使用apktool或jadx
        """
        results = {"output_dir": None, "tool_output": {}}

        output_dir = output_dir or f"/tmp/decompiled_{os.path.basename(apk_path)}"

        # 使用apktool
        cmd = ["apktool", "d", "-f", "-o", output_dir, apk_path]
        output = self.run_command(cmd, timeout=600)
        results["tool_output"]["apktool"] = output

        if output["success"]:
            results["output_dir"] = output_dir

        return results

    def jadx_decompile(self, apk_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        使用jadx反编译为Java源码
        """
        results = {"output_dir": None, "tool_output": {}}

        output_dir = output_dir or f"/tmp/jadx_{os.path.basename(apk_path)}"

        cmd = ["jadx", "-d", output_dir, apk_path]
        output = self.run_command(cmd, timeout=900)
        results["tool_output"]["jadx"] = output

        if output["success"]:
            results["output_dir"] = output_dir

        return results

    def analyze_manifest(self, apk_path: str) -> Dict[str, Any]:
        """
        分析AndroidManifest.xml

        检查安全配置
        """
        results = {
            "security_issues": [],
            "exported_components": [],
            "dangerous_permissions": [],
        }

        # 首先反编译
        decompile_result = self.decompile_apk(apk_path)
        if not decompile_result.get("output_dir"):
            return {"error": "反编译失败"}

        manifest_path = os.path.join(decompile_result["output_dir"], "AndroidManifest.xml")

        if not os.path.exists(manifest_path):
            return {"error": "找不到AndroidManifest.xml"}

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Android namespace
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            # 检查debuggable
            app = root.find("application")
            if app is not None:
                debuggable = app.get("{http://schemas.android.com/apk/res/android}debuggable")
                if debuggable == "true":
                    results["security_issues"].append({
                        "severity": "high",
                        "issue": "应用可调试 (debuggable=true)",
                        "risk": "攻击者可以调试应用获取敏感信息",
                    })

                # 检查allowBackup
                allow_backup = app.get("{http://schemas.android.com/apk/res/android}allowBackup")
                if allow_backup != "false":
                    results["security_issues"].append({
                        "severity": "medium",
                        "issue": "允许备份 (allowBackup=true)",
                        "risk": "攻击者可以备份应用数据",
                    })

            # 检查导出的组件
            for component_type in ["activity", "service", "receiver", "provider"]:
                for component in root.findall(f".//{component_type}"):
                    name = component.get("{http://schemas.android.com/apk/res/android}name")
                    exported = component.get("{http://schemas.android.com/apk/res/android}exported")

                    # 检查intent-filter
                    has_intent_filter = component.find("intent-filter") is not None

                    if exported == "true" or (has_intent_filter and exported != "false"):
                        results["exported_components"].append({
                            "type": component_type,
                            "name": name,
                            "exported": exported or "implicit",
                        })

            # 危险权限列表
            dangerous_perms = [
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.READ_CALENDAR",
                "android.permission.WRITE_CALENDAR",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
            ]

            for perm in root.findall(".//uses-permission"):
                perm_name = perm.get("{http://schemas.android.com/apk/res/android}name")
                if perm_name in dangerous_perms:
                    results["dangerous_permissions"].append(perm_name)

        except ET.ParseError as e:
            results["error"] = f"XML解析错误: {e}"

        return results

    def search_hardcoded_secrets(self, apk_path: str) -> Dict[str, Any]:
        """
        搜索硬编码的敏感信息

        API密钥、密码、私钥等
        """
        results = {"secrets": [], "tool_output": {}}

        # 反编译
        decompile_result = self.decompile_apk(apk_path)
        if not decompile_result.get("output_dir"):
            return {"error": "反编译失败"}

        output_dir = decompile_result["output_dir"]

        # 定义敏感信息模式
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', "API Key"),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
            (r'(?i)(secret|token)\s*[=:]\s*["\']([^"\']+)["\']', "Secret/Token"),
            (r'(?i)(aws[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
            (r'(?i)(aws[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key"),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Private Key"),
            (r'(?i)firebase[a-z]*\s*[=:]\s*["\']([^"\']+)["\']', "Firebase Config"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
            (r'(?i)jdbc:.*:\/\/[^\s"\']+', "Database Connection String"),
        ]

        # 搜索smali代码
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith(('.smali', '.java', '.xml', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            for pattern, secret_type in secret_patterns:
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    results["secrets"].append({
                                        "type": secret_type,
                                        "file": file_path.replace(output_dir, ""),
                                        "value": match if isinstance(match, str) else match[-1],
                                    })
                    except:
                        pass

        # 去重
        seen = set()
        unique_secrets = []
        for secret in results["secrets"]:
            key = f"{secret['type']}:{secret['value']}"
            if key not in seen:
                seen.add(key)
                unique_secrets.append(secret)
        results["secrets"] = unique_secrets

        return results

    def detect_protection(self, apk_path: str) -> Dict[str, Any]:
        """
        检测APK保护措施

        加固、混淆、反调试等
        """
        results = {"protections": [], "packers": []}

        # 检查常见加固特征
        packer_signatures = {
            "Qihoo 360": ["libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so"],
            "Baidu": ["libbaiduprotect.so", "libbd*.so"],
            "Tencent Legu": ["libshell*.so", "libtxAppProtect.so"],
            "Alibaba": ["libsgmain.so", "libsgsecuritybody.so"],
            "ijiami": ["libexec.so", "libexecmain.so"],
            "Bangcle": ["libsecexe.so", "libsecmain.so"],
            "APKProtect": ["libAPKProtect.so"],
        }

        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                file_list = z.namelist()

                for packer, signatures in packer_signatures.items():
                    for sig in signatures:
                        if any(sig in f for f in file_list):
                            results["packers"].append(packer)
                            break

                # 检查是否有native库
                has_native = any("lib/" in f and f.endswith(".so") for f in file_list)
                if has_native:
                    results["protections"].append("Native库保护")

                # 检查classes.dex数量（多dex可能表示加固）
                dex_count = sum(1 for f in file_list if f.endswith(".dex"))
                if dex_count > 1:
                    results["protections"].append(f"MultiDex ({dex_count}个dex)")

        except zipfile.BadZipFile:
            return {"error": "无效的APK文件"}

        return results


class MobSFAnalyzer:
    """
    MobSF集成

    使用Mobile Security Framework进行自动化分析
    """

    def __init__(self, api_url: str = "http://localhost:8000",
                 api_key: str = None):
        self.api_url = api_url
        self.api_key = api_key

    def upload_and_scan(self, file_path: str) -> Dict[str, Any]:
        """
        上传文件并扫描
        """
        results = {"scan_id": None, "report": None}

        try:
            import requests

            # 上传
            files = {"file": open(file_path, "rb")}
            headers = {"Authorization": self.api_key} if self.api_key else {}

            response = requests.post(
                f"{self.api_url}/api/v1/upload",
                files=files,
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                results["scan_id"] = data.get("hash")

                # 开始扫描
                scan_response = requests.post(
                    f"{self.api_url}/api/v1/scan",
                    data={"hash": results["scan_id"]},
                    headers=headers,
                )

                if scan_response.status_code == 200:
                    results["report"] = scan_response.json()

        except ImportError:
            results["error"] = "需要安装requests: pip install requests"
        except Exception as e:
            results["error"] = str(e)

        return results


class FridaHooker:
    """
    Frida动态分析工具

    用于Hook Android/iOS应用
    """

    def __init__(self):
        self.scripts = {}

    def get_common_hooks(self) -> Dict[str, str]:
        """
        获取常用的Frida脚本
        """
        return {
            "ssl_pinning_bypass": '''
Java.perform(function() {
    // 绕过SSL Pinning
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManagerImpl = Java.registerClass({
        name: 'com.bypass.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    console.log('[+] SSL Pinning Bypassed');
});
''',
            "root_detection_bypass": '''
Java.perform(function() {
    // 绕过Root检测
    var RootCheck = Java.use('com.scottyab.rootbeer.RootBeer');
    RootCheck.isRooted.implementation = function() {
        console.log('[+] Root check bypassed');
        return false;
    };
});
''',
            "log_crypto": '''
Java.perform(function() {
    // 记录加密操作
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher.doFinal] Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[Cipher.doFinal] Output: ' + bytesToHex(result));
        return result;
    };
});

function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}
''',
            "http_traffic": '''
Java.perform(function() {
    // 记录HTTP流量
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');

    var Interceptor = Java.registerClass({
        name: 'com.hook.LogInterceptor',
        implements: [Java.use('okhttp3.Interceptor')],
        methods: {
            intercept: function(chain) {
                var request = chain.request();
                console.log('[HTTP] ' + request.method() + ' ' + request.url().toString());
                return chain.proceed(request);
            }
        }
    });

    console.log('[+] HTTP Traffic Logger Active');
});
''',
        }

    def generate_hook_command(self, package_name: str,
                             script_name: str) -> str:
        """
        生成Frida命令
        """
        scripts = self.get_common_hooks()
        if script_name not in scripts:
            return f"# 未知脚本: {script_name}"

        # 保存脚本到临时文件
        script_path = f"/tmp/frida_{script_name}.js"
        with open(script_path, 'w') as f:
            f.write(scripts[script_name])

        return f"frida -U -f {package_name} -l {script_path}"


class IOSAnalyzer:
    """iOS应用分析工具"""

    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """
        分析IPA文件
        """
        results = {"info": {}, "files": [], "security_issues": []}

        try:
            with zipfile.ZipFile(ipa_path, 'r') as z:
                file_list = z.namelist()

                # 查找Info.plist
                for f in file_list:
                    if f.endswith("Info.plist"):
                        # 提取并解析
                        with z.open(f) as plist_file:
                            import plistlib
                            try:
                                plist_data = plistlib.load(plist_file)
                                results["info"] = {
                                    "bundle_id": plist_data.get("CFBundleIdentifier"),
                                    "version": plist_data.get("CFBundleShortVersionString"),
                                    "min_ios": plist_data.get("MinimumOSVersion"),
                                }
                            except:
                                pass
                        break

                # 查找二进制文件
                for f in file_list:
                    if "/Payload/" in f and not f.endswith("/"):
                        results["files"].append(f)

                # 检查是否加密
                for f in file_list:
                    if f.endswith((".app", "")) and not "/" in f.split("Payload/")[-1]:
                        # 这是主二进制
                        results["main_binary"] = f

        except zipfile.BadZipFile:
            results["error"] = "无效的IPA文件"

        return results


class MobileSecurityScanner:
    """
    移动应用安全综合扫描器
    """

    def __init__(self):
        self.apk_analyzer = APKAnalyzer()
        self.ios_analyzer = IOSAnalyzer()
        self.frida_hooker = FridaHooker()

    def auto_scan(self, file_path: str) -> Dict[str, Any]:
        """
        自动扫描移动应用
        """
        results = {
            "file": file_path,
            "platform": None,
            "scan_results": {},
            "security_issues": [],
            "recommendations": [],
        }

        file_lower = file_path.lower()

        if file_lower.endswith(".apk"):
            results["platform"] = "Android"

            print(f"[*] 扫描Android APK: {file_path}")

            # 基本信息
            print("[*] 步骤1: 获取APK信息")
            info = self.apk_analyzer.get_apk_info(file_path)
            results["scan_results"]["basic_info"] = info

            # Manifest分析
            print("[*] 步骤2: 分析AndroidManifest")
            manifest = self.apk_analyzer.analyze_manifest(file_path)
            results["scan_results"]["manifest"] = manifest
            if manifest.get("security_issues"):
                results["security_issues"].extend(manifest["security_issues"])

            # 硬编码秘密
            print("[*] 步骤3: 搜索硬编码敏感信息")
            secrets = self.apk_analyzer.search_hardcoded_secrets(file_path)
            results["scan_results"]["secrets"] = secrets
            if secrets.get("secrets"):
                results["security_issues"].append({
                    "severity": "high",
                    "issue": f"发现{len(secrets['secrets'])}个硬编码的敏感信息",
                })

            # 保护检测
            print("[*] 步骤4: 检测保护措施")
            protection = self.apk_analyzer.detect_protection(file_path)
            results["scan_results"]["protection"] = protection

            # 生成建议
            if not protection.get("packers"):
                results["recommendations"].append("建议使用加固方案保护APK")

            if manifest.get("exported_components"):
                results["recommendations"].append(
                    f"建议检查{len(manifest['exported_components'])}个导出组件的安全性"
                )

        elif file_lower.endswith(".ipa"):
            results["platform"] = "iOS"

            print(f"[*] 扫描iOS IPA: {file_path}")

            # 基本分析
            ipa_result = self.ios_analyzer.analyze_ipa(file_path)
            results["scan_results"]["basic_info"] = ipa_result

        else:
            results["error"] = "不支持的文件格式"

        print(f"\n[+] 扫描完成")
        print(f"    发现安全问题: {len(results['security_issues'])}个")

        return results

    def decompile_apk(self, apk_path: str, output_dir: str = "") -> Dict[str, Any]:
        """
        APK反编译分析 - 代理到APKAnalyzer

        Args:
            apk_path: APK文件路径
            output_dir: 输出目录

        Returns:
            反编译结果和发现的敏感信息
        """
        results = {
            "apk_path": apk_path,
            "decompile_results": {},
            "sensitive_info": [],
            "error": None
        }

        try:
            # 基本反编译
            decompile_result = self.apk_analyzer.decompile_apk(apk_path, output_dir if output_dir else None)
            results["decompile_results"]["apktool"] = decompile_result

            # 使用jadx获取Java源码
            jadx_result = self.apk_analyzer.jadx_decompile(apk_path)
            results["decompile_results"]["jadx"] = jadx_result

            # 搜索敏感信息
            if decompile_result.get("output_dir"):
                secrets = self.apk_analyzer.search_hardcoded_secrets(apk_path)
                results["sensitive_info"] = secrets.get("secrets", [])
                results["output_dir"] = decompile_result["output_dir"]

        except Exception as e:
            results["error"] = str(e)

        return results

    def hook_app(self, target: str, script: str = "", hook_type: str = "auto") -> Dict[str, Any]:
        """
        Frida动态Hook - 代理到FridaHooker

        Args:
            target: 目标应用包名或进程
            script: 自定义Frida脚本
            hook_type: Hook类型

        Returns:
            Hook执行结果
        """
        results = {
            "target": target,
            "hook_type": hook_type,
            "success": False,
            "output": None,
            "error": None
        }

        try:
            if hook_type == "ssl_bypass":
                results["output"] = self.frida_hooker.ssl_pinning_bypass(target)
                results["success"] = True
            elif hook_type == "root_bypass":
                results["output"] = self.frida_hooker.root_detection_bypass(target)
                results["success"] = True
            elif script:
                results["output"] = self.frida_hooker.run_script(target, script)
                results["success"] = True
            else:
                # 自动模式 - 尝试SSL bypass
                results["output"] = self.frida_hooker.ssl_pinning_bypass(target)
                results["success"] = True

        except Exception as e:
            results["error"] = str(e)

        return results


# 导出
__all__ = [
    "APKAnalyzer",
    "IOSAnalyzer",
    "MobSFAnalyzer",
    "FridaHooker",
    "MobileSecurityScanner",
    "APKInfo",
]
