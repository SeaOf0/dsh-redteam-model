# e0e1-wx-gui

![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D4)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB)
![GUI](https://img.shields.io/badge/GUI-PySide6-41CD52)

一款面向 Windows 的微信小程序本地分析 GUI 工具，提供小程序包监控、自动反编译、mcp+skill自动化渗透、js注入、正则匹配、代码优化、DevTools CDP、路由查看、云函数分析以及常用加密解密辅助能力。

> 本项目仅用于授权安全研究、学习和调试场景，请勿用于未授权目标或违反相关法律法规的用途。

## 项目简介

`e0e1-wx-gui` 主要用于辅助分析本机运行中的微信小程序。工具会围绕小程序包捕获、反编译、代码检索、动态调试和云函数分析等场景提供图形化支持，降低手工整理和来回切换工具的成本。

如果你是第一次使用，建议先阅读 [tools.md](./tools.md) 中的配置说明，再启动程序。

## 主要能力

- 自动检测正在运行的小程序，并记录主包、分包等加密包信息。
- 自动反编译小程序源代码，便于后续审计和静态分析。
- 内置正则匹配、文件搜索和定位能力，支持快速跳转到目标内容。
- 支持对反编译后的代码进行格式化和可读性优化。
- 提供 DevTools CDP 调试辅助，方便接入浏览器调试链路。
- 支持读取小程序路由并辅助跳转到目标页面。
- 支持云函数静态扫描，并可手动触发目标云函数。
- 提供常用加密解密辅助能力，便于还原和分析数据。

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10 / Windows 11 |
| Python | 3.10+、3.11+ |
| 微信环境 | 本机需存在受支持的微信小程序运行环境 |
| 当前配置覆盖版本 | `11581` - `19459` |

## 快速开始

进入项目目录后，建议先创建虚拟环境，再安装依赖并启动程序：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

启动后会打开 `e0e1-wx-gui` 图形界面。

## 使用前必读

首次使用请先阅读 [tools.md](./tools.md)，其中包含：  （一定要阅读！！！！！！！！！！！！！！！！）

- 微信小程序运行环境版本的确认方法
- 缺失配置文件时的补充方式
- 应用内目录配置说明
- 抓包/代理转发导致无法回连时的处理方法
- 各个核心功能的操作示例

## 致谢

感谢以下开源项目提供的思路和能力支持：

- [r3x5ur/unveilr](https://github.com/r3x5ur/unveilr)
- [Ackites/KillWxapkg](https://github.com/Ackites/KillWxapkg)
- [x0tools/WeChatOpenDevTools](https://github.com/x0tools/WeChatOpenDevTools)
- [mrknow001/wx_sessionkey_decrypt](https://github.com/mrknow001/wx_sessionkey_decrypt)
- [JaveleyQAQ/WeChatOpenDevTools-Python](https://github.com/JaveleyQAQ/WeChatOpenDevTools-Python)
- [Spade-sec/First](https://github.com/Spade-sec/First)
