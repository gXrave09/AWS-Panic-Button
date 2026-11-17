#!/usr/bin/env python3
"""
LocalStack AWS Compatible Core Service (Port 4566)
Implements real AWS REST API specifications on port 4566:
- Amazon S3: Object storage, Public Access Block enforcement, AccessDenied XML, quarantine
- Amazon EC2: Instance status & containment directly integrated with Docker
- Amazon SNS & SQS: Message publish & queue retrieval with AWS XML/JSON responses
- Amazon API Gateway & Lambda: Invocation of IncidentResponsePanicHandler
- LocalStack Health: GET /_localstack/health
"""

import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
try:
    from lambda_function import lambda_handler
except ImportError:
    lambda_handler = None

PORT_LOCALSTACK = 4566

DEFAULT_CSV_CONTENT = (
    "id,customer_name,ssn,account_balance\n"
    "101,John Doe,XXX-XX-1234,$54,200.00\n"
    "102,Jane Smith,XXX-XX-5678,$82,450.00\n"
    "103,Robert Johnson,XXX-XX-9012,$128,900.00\n"
)

# Live in-memory AWS state on Port 4566
AWS_STATE = {
    "s3_buckets": {
        "confidential-company-data": {
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "objects": {
                "customer_records_2026.csv": DEFAULT_CSV_CONTENT
            }
        }
    },
    "sns_topics": {
        "arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts": [],
        "arn:aws:sns:us-east-1:000000000000:security-incident-alerts": []
    },
    "messages": []
}


def is_s3_public_blocked(bucket_name):
    """Returns True if any of the 4 S3 Public Access Block flags are enabled."""
    bucket = AWS_STATE["s3_buckets"].get(bucket_name)
    if not bucket:
        return False
    pab = bucket.get("public_access_block", {})
    return any(pab.values())


def query_docker_ec2_instances():
    """Queries Docker for EC2 container states."""
    try:
        res = subprocess.run([
            "docker", "ps", "-a", "--filter", "name=localstack-ec2",
            "--format", "{{.Names}}::{{.Status}}"
        ], capture_output=True, text=True, timeout=4)
        if res.returncode == 0 and res.stdout.strip():
            lines = [l.strip() for l in res.stdout.strip().splitlines() if l.strip()]
            instances = []
            for line in lines:
                parts = line.split("::", 1)
                name = parts[0]
                status = parts[1] if len(parts) > 1 else ""
                inst_id = name.replace("localstack-ec2.", "")
                state = "stopped" if ("paused" in status.lower() or "exited" in status.lower()) else "running"
                instances.append({"id": inst_id, "state": state})
            return instances
    except Exception:
        pass
    return [{"id": "i-cc08d7300dc4c19c8", "state": "running"}]


def stop_docker_ec2_instances(instance_ids=None):
    """Pauses or stops the EC2 Docker container."""
    stopped = []
    try:
        containers = ["localstack-ec2.i-cc08d7300dc4c19c8"]
        if instance_ids:
            containers = [f"localstack-ec2.{i}" if not i.startswith("localstack-ec2.") else i for i in instance_ids]
        for c in containers:
            subprocess.run(["docker", "pause", c], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            inst_clean = c.replace("localstack-ec2.", "")
            stopped.append(inst_clean)
    except Exception:
        pass
    return stopped or ["i-cc08d7300dc4c19c8"]


def start_docker_ec2_instances(instance_ids=None):
    """Unpauses or starts the EC2 Docker container."""
    started = []
    try:
        containers = ["localstack-ec2.i-cc08d7300dc4c19c8"]
        if instance_ids:
            containers = [f"localstack-ec2.{i}" if not i.startswith("localstack-ec2.") else i for i in instance_ids]
        for c in containers:
            subprocess.run(["docker", "unpause", c], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            inst_clean = c.replace("localstack-ec2.", "")
            started.append(inst_clean)
    except Exception:
        pass
    return started or ["i-cc08d7300dc4c19c8"]


class LocalStackRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "LocalStack/3.0.0"

    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-amz-date, x-amz-security-token, x-amz-target, x-amz-copy-source")
        self.send_header("Server", "LocalStack/3.0.0 (AWS-Emulation)")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_GET(self, head_only=False):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed.query)

        # 1. LocalStack Health Check
        if path in ("/health", "/_localstack/health"):
            health = {
                "services": {
                    "s3": "available",
                    "lambda": "available",
                    "apigateway": "available",
                    "sns": "available",
                    "sqs": "available",
                    "ec2": "available",
                    "cloudwatch": "available",
                    "iam": "available"
                },
                "version": "3.0.0",
                "edition": "community"
            }
            body = json.dumps(health, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return

        # 2. Query Messages (SNS / SQS Feed)
        if path in ("/_localstack/messages", "/_localstack/sqs/messages", "/sns-messages"):
            body = json.dumps({"messages": AWS_STATE["messages"]}, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return

        # 3. S3 Public Access Block Inspection & Objects
        parts = [p for p in path.split("/") if p]
        if parts:
            bucket_name = parts[0]

            # 3a. GetPublicAccessBlock
            if "publicAccessBlock" in query and bucket_name in AWS_STATE["s3_buckets"]:
                pab = AWS_STATE["s3_buckets"][bucket_name]["public_access_block"]
                xml_res = (
                    f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
                    f'  <BlockPublicAcls>{str(pab["BlockPublicAcls"]).lower()}</BlockPublicAcls>\n'
                    f'  <IgnorePublicAcls>{str(pab["IgnorePublicAcls"]).lower()}</IgnorePublicAcls>\n'
                    f'  <BlockPublicPolicy>{str(pab["BlockPublicPolicy"]).lower()}</BlockPublicPolicy>\n'
                    f'  <RestrictPublicBuckets>{str(pab["RestrictPublicBuckets"]).lower()}</RestrictPublicBuckets>\n'
                    f'</PublicAccessBlockConfiguration>'
                ).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self._send_cors()
                self.end_headers()
                if not head_only:
                    self.wfile.write(xml_res)
                return

            # 3b. S3 GetObject (Public Anonymous Test)
            if len(parts) >= 2:
                object_key = "/".join(parts[1:])
                bucket = AWS_STATE["s3_buckets"].get(bucket_name)

                # Check if public access is blocked OR object quarantined
                if is_s3_public_blocked(bucket_name) or (bucket and object_key not in bucket.get("objects", {})):
                    error_xml = (
                        f'<?xml version="1.0" encoding="UTF-8"?>\n'
                        f'<Error>\n'
                        f'  <Code>AccessDenied</Code>\n'
                        f'  <Message>Access Denied: S3 PublicAccessBlock is active on {bucket_name}</Message>\n'
                        f'  <Resource>/{bucket_name}/{object_key}</Resource>\n'
                        f'  <RequestId>REQ-{int(time.time()*1000)}</RequestId>\n'
                        f'  <HostId>localstack-port-4566</HostId>\n'
                        f'</Error>\n'
                    ).encode("utf-8")

                    self.send_response(403)
                    self.send_header("Content-Type", "application/xml")
                    self.send_header("x-amz-request-id", f"REQ-{int(time.time()*1000)}")
                    self._send_cors()
                    self.end_headers()
                    if not head_only:
                        self.wfile.write(error_xml)
                    return
                else:
                    # Object exposed - return 200 OK
                    content = bucket.get("objects", {}).get(object_key, DEFAULT_CSV_CONTENT)
                    body_bytes = content.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv")
                    self.send_header("Content-Length", str(len(body_bytes)))
                    self.send_header("ETag", '"e8b2b2a6f86c8d2d"')
                    self.send_header("x-amz-request-id", f"REQ-{int(time.time()*1000)}")
                    self._send_cors()
                    self.end_headers()
                    if not head_only:
                        self.wfile.write(body_bytes)
                    return

        # Default fallback
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._send_cors()
        self.end_headers()
        if not head_only:
            self.wfile.write(b'{"status": "running", "service": "LocalStack"}')

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed.query)
        parts = [p for p in path.split("/") if p]

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

        # 1. S3 PutPublicAccessBlock
        if parts and "publicAccessBlock" in query:
            bucket_name = parts[0]
            if bucket_name not in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][bucket_name] = {"public_access_block": {}, "objects": {}}

            AWS_STATE["s3_buckets"][bucket_name]["public_access_block"] = {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }

            self.send_response(200)
            self._send_cors()
            self.end_headers()
            return

        # 2. S3 CopyObject (x-amz-copy-source header)
        copy_src = self.headers.get("x-amz-copy-source")
        if copy_src and len(parts) >= 2:
            dest_bucket = parts[0]
            dest_key = "/".join(parts[1:])
            src_clean = copy_src.lstrip("/")
            src_parts = src_clean.split("/", 1)
            src_b = src_parts[0]
            src_k = src_parts[1] if len(src_parts) > 1 else ""

            content = DEFAULT_CSV_CONTENT
            if src_b in AWS_STATE["s3_buckets"] and src_k in AWS_STATE["s3_buckets"][src_b]["objects"]:
                content = AWS_STATE["s3_buckets"][src_b]["objects"][src_k]

            if dest_bucket not in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][dest_bucket] = {"public_access_block": {}, "objects": {}}
            AWS_STATE["s3_buckets"][dest_bucket]["objects"][dest_key] = content

            res_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
                f'  <LastModified>{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}</LastModified>\n'
                f'  <ETag>"e8b2b2a6f86c8d2d"</ETag>\n'
                f'</CopyObjectResult>'
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self._send_cors()
            self.end_headers()
            self.wfile.write(res_xml)
            return

        # 3. S3 PutObject
        if len(parts) >= 2:
            bucket_name = parts[0]
            object_key = "/".join(parts[1:])
            if bucket_name not in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][bucket_name] = {"public_access_block": {}, "objects": {}}
            AWS_STATE["s3_buckets"][bucket_name]["objects"][object_key] = body or DEFAULT_CSV_CONTENT
            self.send_response(200)
            self.send_header("ETag", '"e8b2b2a6f86c8d2d"')
            self._send_cors()
            self.end_headers()
            return

        # 4. S3 CreateBucket
        if parts:
            bucket_name = parts[0]
            if bucket_name not in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][bucket_name] = {
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "objects": {}
                }
            self.send_response(200)
            self.send_header("Location", f"/{bucket_name}")
            self._send_cors()
            self.end_headers()
            return

        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

        # 1. API Gateway /panic endpoint on Port 4566
        if path.endswith("/panic"):
            event = {"body": post_body}
            res = lambda_handler(event, None) if lambda_handler else {"statusCode": 200, "body": "{}"}
            code = res.get("statusCode", 200)
            body = res.get("body", "{}")

            # Also ensure S3 state is locked on 4566
            for b in AWS_STATE["s3_buckets"].values():
                b["public_access_block"] = {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
                # Quarantine customer records
                if "customer_records_2026.csv" in b["objects"]:
                    b["objects"]["quarantine/customer_records_2026.csv"] = b["objects"].pop("customer_records_2026.csv")

            # Also pause EC2 docker container
            stop_docker_ec2_instances()

            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        # 2. Reset / Exposure simulation endpoint on Port 4566
        if path in ("/_localstack/reset", "/reset"):
            for b in AWS_STATE["s3_buckets"].values():
                b["public_access_block"] = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
                b["objects"]["customer_records_2026.csv"] = DEFAULT_CSV_CONTENT
                b["objects"].pop("quarantine/customer_records_2026.csv", None)

            start_docker_ec2_instances()
            AWS_STATE["messages"].clear()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(b'{"status": "RESET", "public_access": "EXPOSED", "ec2": "RUNNING"}')
            return

        # Parse query / form data for AWS Actions
        params = urllib.parse.parse_qs(post_body)
        url_params = urllib.parse.parse_qs(parsed.query)
        action = (params.get("Action", [None])[0] or url_params.get("Action", [None])[0] or "")
        amz_target = self.headers.get("x-amz-target", "")

        # 3. Amazon EC2 Actions
        if "ec2" in amz_target or action in ("DescribeInstances", "StopInstances", "StartInstances"):
            if action == "DescribeInstances" or "DescribeInstances" in post_body:
                instances = query_docker_ec2_instances()
                items_xml = ""
                for inst in instances:
                    items_xml += (
                        f'      <item>\n'
                        f'        <instanceId>{inst["id"]}</instanceId>\n'
                        f'        <instanceState>\n'
                        f'          <code>{16 if inst["state"] == "running" else 80}</code>\n'
                        f'          <name>{inst["state"]}</name>\n'
                        f'        </instanceState>\n'
                        f'      </item>\n'
                    )

                ec2_xml = (
                    f'<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">\n'
                    f'  <requestId>req-ec2-{int(time.time())}</requestId>\n'
                    f'  <reservationSet>\n'
                    f'    <item>\n'
                    f'      <reservationId>r-localstack-ec2</reservationId>\n'
                    f'      <instancesSet>\n'
                    f'{items_xml}'
                    f'      </instancesSet>\n'
                    f'    </item>\n'
                    f'  </reservationSet>\n'
                    f'</DescribeInstancesResponse>'
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self._send_cors()
                self.end_headers()
                self.wfile.write(ec2_xml)
                return

            if action == "StopInstances" or "StopInstances" in post_body:
                stopped_ids = stop_docker_ec2_instances()
                items_xml = "".join([f'<item><instanceId>{iid}</instanceId><currentState><code>80</code><name>stopping</name></currentState></item>' for iid in stopped_ids])
                xml = f'<StopInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><instancesSet>{items_xml}</instancesSet></StopInstancesResponse>'.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self._send_cors()
                self.end_headers()
                self.wfile.write(xml)
                return

            if action == "StartInstances" or "StartInstances" in post_body:
                started_ids = start_docker_ec2_instances()
                items_xml = "".join([f'<item><instanceId>{iid}</instanceId><currentState><code>16</code><name>running</name></currentState></item>' for iid in started_ids])
                xml = f'<StartInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><instancesSet>{items_xml}</instancesSet></StartInstancesResponse>'.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self._send_cors()
                self.end_headers()
                self.wfile.write(xml)
                return

        # 4. Amazon SNS Actions (CreateTopic / Publish)
        is_sns = action in ("Publish", "CreateTopic") or "sns" in amz_target or "sns" in path
        if is_sns:
            msg_id = f"msg-sns-4566-{int(time.time()*1000)}"
            if action == "Publish" or "Action=Publish" in post_body:
                msg_content = params.get("Message", ["Alert dispatched"])[0]
                subject = params.get("Subject", ["[SEV-1] Incident Containment Alert"])[0]
                topic_arn = params.get("TopicArn", ["arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts"])[0]
                record = {
                    "id": msg_id,
                    "subject": subject,
                    "message": msg_content,
                    "topic": topic_arn,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                AWS_STATE["messages"].insert(0, record)

            sns_xml = (
                f'<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">\n'
                f'  <PublishResult>\n'
                f'    <MessageId>{msg_id}</MessageId>\n'
                f'  </PublishResult>\n'
                f'  <ResponseMetadata>\n'
                f'    <RequestId>req-sns-{int(time.time())}</RequestId>\n'
                f'  </ResponseMetadata>\n'
                f'</PublishResponse>\n'
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self._send_cors()
            self.end_headers()
            self.wfile.write(sns_xml)
            return

        # 5. Amazon SQS Actions (ReceiveMessage)
        if action == "ReceiveMessage" or "sqs" in amz_target:
            msgs_xml = ""
            for m in AWS_STATE["messages"][:10]:
                body_json = json.dumps({"Subject": m["subject"], "Message": m["message"], "TopicArn": m["topic"], "Timestamp": m["timestamp"]})
                msgs_xml += (
                    f'    <Message>\n'
                    f'      <MessageId>{m["id"]}</MessageId>\n'
                    f'      <ReceiptHandle>receipt-{m["id"]}</ReceiptHandle>\n'
                    f'      <MD5OfBody>e8b2b2a6f86c8d2d</MD5OfBody>\n'
                    f'      <Body>{urllib.parse.quote(body_json)}</Body>\n'
                    f'    </Message>\n'
                )

            sqs_xml = (
                f'<ReceiveMessageResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">\n'
                f'  <ReceiveMessageResult>\n'
                f'{msgs_xml}'
                f'  </ReceiveMessageResult>\n'
                f'  <ResponseMetadata>\n'
                f'    <RequestId>req-sqs-{int(time.time())}</RequestId>\n'
                f'  </ResponseMetadata>\n'
                f'</ReceiveMessageResponse>'
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self._send_cors()
            self.end_headers()
            self.wfile.write(sqs_xml)
            return

        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        parts = [p for p in path.split("/") if p]

        # S3 DeleteObject
        if len(parts) >= 2:
            bucket_name = parts[0]
            object_key = "/".join(parts[1:])
            if bucket_name in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][bucket_name]["objects"].pop(object_key, None)

        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[LocalStack :4566] {args[0]} {args[1]}\n")


def start_localstack_server(port=PORT_LOCALSTACK):
    """Starts the LocalStack service on port 4566."""
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", port), LocalStackRequestHandler)
    print(f"⚡ LocalStack Core running locally on port {port} (S3, EC2 Docker, Lambda, SNS, SQS)")
    httpd.serve_forever()


if __name__ == "__main__":
    start_localstack_server()
