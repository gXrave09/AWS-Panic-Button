#!/usr/bin/env bash
# ============================================================
# Connects directly to the EC2 container (Ubuntu 22.04)
# ============================================================

CONTAINER="localstack-ec2.i-cc08d7300dc4c19c8"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_KEY="${SCRIPT_DIR}/infra/ec2/key.pem"

echo "Connecting to EC2 instance (Ubuntu 22.04)..."

# If docker is accessible directly, use docker exec for a clean shell
if command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${CONTAINER}"; then
    if [ $# -eq 0 ]; then
        exec docker exec -it "${CONTAINER}" /bin/bash
    else
        exec docker exec -i "${CONTAINER}" /bin/bash -c "$*"
    fi
fi

# Fallback to SSH with mirrored key
SAFE_KEY="/tmp/ec2_key_${USER:-user}.pem"
cp -f "${ORIGINAL_KEY}" "${SAFE_KEY}" 2>/dev/null || true
chmod 600 "${SAFE_KEY}" 2>/dev/null || true

ssh -i "${SAFE_KEY}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 9345 \
    root@localhost "$@"
