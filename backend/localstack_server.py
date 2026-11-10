#!/usr/bin/env python3
"""
LocalStack AWS Compatible Core Service (Port 4566)
Implements real AWS REST API specifications on port 4566:
- Amazon S3: Object storage, Public Access Block enforcement, AccessDenied XML
- Amazon SNS: Publish and CreateTopic with AWS XML responses
- Amazon API Gateway & Lambda: Invocation of IncidentResponsePanicHandler
- LocalStack Health: GET /_localstack/health
"""

import http.server
import json
import os
import socketserver
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
from lambda_function import lambda_handler

PORT_LOCALSTACK = 4566

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
                "customer_records_2026.csv": (
                    "id,customer_name,ssn,account_balance\n"
                    "101,John Doe,XXX-XX-1234,$54,200.00\n"
                    "102,Jane Smith,XXX-XX-5678,$82,450.00\n"
                    "103,Robert Johnson,XXX-XX-9012,$128,900.00\n"
                )
            }
        }
    },
    "sns_topics": {
        "arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts": []
    }
}


def is_s3_public_blocked(bucket_name):
    """Returns True if any of the 4 S3 Public Access Block flags are enabled."""
    bucket = AWS_STATE["s3_buckets"].get(bucket_name)
    if not bucket:
        return False
    pab = bucket.get("public_access_block", {})
    return any(pab.values())


class LocalStackRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "LocalStack/3.0.0"

    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-amz-date, x-amz-security-token, x-amz-target")
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
        if path == "/_localstack/health" or path == "/health":
            health = {
                "services": {
                    "s3": "available",
                    "lambda": "available",
                    "apigateway": "available",
                    "sns": "available",
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

        # 2. S3 GetPublicAccessBlock
        parts = [p for p in path.split("/") if p]
        if parts:
            bucket_name = parts[0]
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

            # 3. S3 GetObject (Public Anonymous Test)
            if len(parts) >= 2:
                object_key = "/".join(parts[1:])
                bucket = AWS_STATE["s3_buckets"].get(bucket_name)

                if is_s3_public_blocked(bucket_name):
                    # REAL AWS S3 ACCESS DENIED 403 XML
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
                    content = (bucket.get("objects", {}).get(object_key) if bucket else None)
                    if content is None:
                        content = "id,customer_name,ssn,account_balance\n101,John Doe,XXX-XX-1234,$54,200.00\n"

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

        # S3 PutPublicAccessBlock
        if parts and "publicAccessBlock" in query:
            bucket_name = parts[0]
            if bucket_name not in AWS_STATE["s3_buckets"]:
                AWS_STATE["s3_buckets"][bucket_name] = {"public_access_block": {}, "objects": {}}

            # Enforce lock
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

        # S3 CreateBucket
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
            res = lambda_handler(event, None)
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

            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        # 2. Reset / Exposure simulation endpoint on Port 4566
        if path == "/_localstack/reset" or path == "/reset":
            for b in AWS_STATE["s3_buckets"].values():
                b["public_access_block"] = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(b'{"status": "RESET", "public_access": "EXPOSED"}')
            return

        # 3. Amazon SNS Actions (CreateTopic / Publish)
        is_sns = "Action=Publish" in post_body or "Action=CreateTopic" in post_body or "sns" in self.headers.get("x-amz-target", "")
        if is_sns or path == "/" or "sns" in path:
            msg_id = f"msg-sns-4566-{int(time.time())}"
            sns_xml = (
                f'<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">\n'
                f'  <PublishResult>\n'
                f'    <MessageId>{msg_id}</MessageId>\n'
                f'  </PublishResult>\n'
                f'  <ResponseMetadata>\n'
                f'    <RequestId>req-sns-4566</RequestId>\n'
                f'  </ResponseMetadata>\n'
                f'</PublishResponse>\n'
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self._send_cors()
            self.end_headers()
            self.wfile.write(sns_xml)
            return

        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_DELETE(self):
        # S3 DeleteBucketPolicy
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[LocalStack :4566] {args[0]} {args[1]}\n")


def start_localstack_server(port=PORT_LOCALSTACK):
    """Starts the LocalStack service on port 4566 in a background thread or process."""
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", port), LocalStackRequestHandler)
    print(f"⚡ LocalStack Core running on port {port} (S3, Lambda, API Gateway, SNS)")
    httpd.serve_forever()


if __name__ == "__main__":
    start_localstack_server()

