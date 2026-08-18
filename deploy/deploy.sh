#!/usr/bin/env bash
# 跨平台 shim：真正的部署逻辑在 deploy.mjs（node 实现，win/mac/linux 通用）。
exec node "$(dirname "$0")/deploy.mjs" "$@"
