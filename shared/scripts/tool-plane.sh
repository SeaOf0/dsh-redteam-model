#!/bin/sh
# tool-plane 探测合并：一次跑完期望工具集的 command -v 探测，输出紧凑表（直接登记 evidence-index tool-plane 节）
# 用法: ./tool-plane.sh <tool1> <tool2> ...   （参数 = 本模式 playbook 附录 A/B 的期望工具清单）
# 可选: VERSION=1 时附带版本探测（仅在系统有 timeout 命令时逐个取 --version 首行，3 秒超时防交互卡死）
for t in "$@"; do
	if p=$(command -v "$t" 2>/dev/null); then
		v=""
		if [ "$VERSION" = "1" ] && command -v timeout >/dev/null 2>&1; then
			v=$(timeout 3 "$t" --version 2>/dev/null | head -1 | cut -c1-48)
		fi
		echo "tool-plane: $t ok${v:+ | $v}"
	else
		echo "tool-plane: $t missing"
	fi
done
