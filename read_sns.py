#!/usr/bin/env python3
"""
View SNS Incident Alert Messages from LocalStack.
Works cross-platform against http://localhost:4566/_localstack/messages or http://localhost:8000/sns-messages.
"""

import json
import sys
import urllib.request

print("============================================================")
print("📬 Fetching latest SNS Incident Messages from LocalStack...")
print("============================================================")

urls = [
    "http://localhost:4566/_localstack/messages",
    "http://localhost:8000/sns-messages",
    "http://localhost:8080/sns-messages"
]

messages = []
for url in urls:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            msgs = data.get("messages", [])
            if msgs:
                messages = msgs
                break
    except Exception:
        pass

if not messages:
    print("No SNS alert messages found yet (topic ready).")
    sys.exit(0)

print(f"Found {len(messages)} alert message(s):\n")
for i, m in enumerate(messages, 1):
    subject = m.get("subject", "N/A")
    topic = m.get("topic", "N/A")
    ts = m.get("timestamp", "N/A")
    msg_text = m.get("message", "")
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

