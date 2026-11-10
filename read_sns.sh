#!/usr/bin/env bash
# ============================================================
# View SNS Incident Alert Messages from LocalStack
# ============================================================

echo "============================================================"
echo "📬 Fetching latest SNS Incident Messages from LocalStack..."
echo "============================================================"

docker exec -i localstack-main awslocal sqs receive-message \
    --queue-url http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/incident-alerts-queue \
    --max-number-of-messages 10 \
    --visibility-timeout 0 \
    --output json 2>/dev/null | python3 -c '
import sys, json

try:
    data = json.load(sys.stdin)
    msgs = data.get("Messages", [])
    if not msgs:
        print("No SNS alert messages found in queue.")
        sys.exit(0)
    print(f"Found {len(msgs)} alert message(s):\n")
    for i, m in enumerate(msgs, 1):
        body = json.loads(m["Body"])
        subject = body.get("Subject", "N/A")
        topic = body.get("TopicArn", "N/A")
        ts = body.get("Timestamp", "N/A")
        msg_text = body.get("Message", "")
        print(f"[{i}] Subject:   {subject}")
        print(f"    TopicArn:  {topic}")
        print(f"    Timestamp: {ts}")
        try:
            parsed_inner = json.loads(msg_text)
            print("    Message (Structured JSON):")
            print(json.dumps(parsed_inner, indent=6))
        except Exception:
            print(f"    Message:   {msg_text}")
        print("-" * 60)
except Exception:
    print("No messages received or queue empty.")
'
