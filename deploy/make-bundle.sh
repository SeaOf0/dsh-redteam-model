#!/usr/bin/env bash
# 跨平台 shim：打包逻辑在 deploy.mjs --bundle。
exec node "$(dirname "$0")/deploy.mjs" --bundle "$@"
