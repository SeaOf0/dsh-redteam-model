# MCP 逆向任务模板

## Observe

- 读取 `target`、`objective`、`requirements`、`boundaries`
- 判断目标类型与 ABI
- 确认是否存在动态设备交互边界

## Observe / Triage

- Manifest / strings / imports / libs / assets 快速分诊
- 判定 `A0-A7`
- 选主工具链与备份链

## Capture / Static

- APK: 组件、入口、权限、资源、网络库、加载点
- SO: 导出符号、JNI 痕迹、加密常量、可疑 syscall

## Capture / Bridge

- `System.loadLibrary`
- `JNI_OnLoad`
- `RegisterNatives`
- `Java_*`

## Capture / Dynamic

- Java hook
- Native hook
- logcat
- 加载器事件

## Close

- 写 task artifact
- 回填 task.json
- 运行 verify-once

