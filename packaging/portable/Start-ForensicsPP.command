#!/bin/sh
# Copyright (c) 2026 DyNooob. MIT License.
cd "$(dirname "$0")" || exit 1
exec python3 ./start_server.py "$@"
