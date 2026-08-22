#!/bin/sh
# 编译 Java 载荷并重新生成 lib/protocol/payloads-java.js（嵌入 base64）。
# 用法：sh payload-src/build.sh   （需要 javac 8+；产物 -g:none 精简、默认包、零外部依赖）
set -e
cd "$(dirname "$0")"
OUT=../lib/protocol/payloads-java.js
CLASSES=../assets/payloads-java
rm -rf "$CLASSES"
mkdir -p "$CLASSES"
javac -g:none -encoding UTF-8 -d "$CLASSES" java/*.java
{
	printf '// dsh-webshell-mgr Java 载荷字节码（payload-src/build.sh 生成，勿手改）。\n'
	printf '// 形态：默认包、纯反射取 Servlet 上下文（PageContext / Object[]{req,resp,sess}）、\n'
	printf '// static final String 占位字段（发送时常量池补丁替换实参）+ 每次发送类名随机化\n'
	printf '// （规避同 ClassLoader 重复 defineClass 的 LinkageError）。\n'
	printf 'export const JAVA_PAYLOADS = {\n'
	for f in "$CLASSES"/*.class; do
		name=$(basename "$f" .class)
		printf '\t%s: "%s",\n' "$name" "$(base64 < "$f" | tr -d '\n')"
	done
	printf '};\n'
} > "$OUT"
echo "built: $OUT"
grep -c '"' "$OUT" >/dev/null
ls -la "$CLASSES"
