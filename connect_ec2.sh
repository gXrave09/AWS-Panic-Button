#!/usr/bin/env bash
# Connects directly to the EC2 container on port 9345
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_PATH="${SCRIPT_DIR}/infra/ec2/key.pem"

echo "Connecting to EC2 instance (Ubuntu 22.04) on localhost:9345..."
ssh -i "${KEY_PATH}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 9345 \
    root@localhost "$@"

