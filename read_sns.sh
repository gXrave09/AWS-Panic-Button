#!/usr/bin/env bash
# ============================================================
# View SNS Incident Alert Messages from LocalStack
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "${SCRIPT_DIR}/read_sns.py" || python "${SCRIPT_DIR}/read_sns.py"
