#!/bin/bash
cd "$(dirname "$0")"
if command -v python3 &>/dev/null; then
    python3 run.py &
elif command -v python &>/dev/null; then
    python run.py &
else
    echo "Python не найден"
    exit 1
fi
