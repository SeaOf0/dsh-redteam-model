#!/usr/bin/env bash
# 统一构建入口：cross-compile via mingw（检测制：command -v x86_64-w64-mingw32-gcc）
set -e
cd "$(dirname "$0")"
CC=$(command -v x86_64-w64-mingw32-gcc || true)
[ -z "$CC" ] && { echo "缺 x86_64-w64-mingw32-gcc（brew install mingw-w64 / apt install mingw-w64）"; exit 1; }
mkdir -p build
TARGETS="${1:-01 03 04 06}"
for t in $TARGETS; do
  d=$(ls -d ${t}-*/ 2>/dev/null | head -1) || true
  [ -z "$d" ] && continue
  mkdir -p "build/$t"
  case "$t" in
    01) $CC -mwindows -o "build/$t/syscall-demo.exe" "$d/main.c" "$d/syscall.o" 2>/dev/null || { $CC -c -o "build/$t/syscall.o" "$d/syscall.asm" && $CC -mwindows -o "build/$t/syscall-demo.exe" "$d/main.c" "build/$t/syscall.o"; } ;;
    03) $CC -mwindows -o "build/$t/etw-patch.exe" "$d/etw_patch.c" ;;
    04) $CC -mwindows -o "build/$t/unhook.exe" "$d/unhook.c" ;;
    06) $CC -mwindows -o "build/$t/hwbp.exe" "$d/hwbp.c" ;;
  esac
  for f in build/$t/*.exe; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | cut -d' ' -f1)  $f  $(date -u +%FT%TZ)" >> build/manifest.txt
  done
done
echo "构建完成："; ls -la build/*/ 2>/dev/null | grep exe || echo "（05 见其 NOTES：先 python3 打包再 mingw 构建）"
