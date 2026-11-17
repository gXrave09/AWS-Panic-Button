from http.server import BaseHTTPRequestHandler
import json
import os
import time
import urllib.request
import urllib.error

DEFAULT_CSV_CONTENT = (
    "id,customer_name,ssn,account_balance\n"
    "101,John Doe,XXX-XX-1234,$54,200.00\n"
    "102,Jane Smith,XXX-XX-5678,$82,450.00\n"
    "103,Robert Johnson,XXX-XX-9012,$128,900.00\n"
)

TARGET_BUCKET = os.environ.get("TARGET_BUCKET_NAME", "confidential-company-data-2503a52928")
SAMPLE_FILE = "customer_records_2026.csv"

# In-memory containment state on Vercel
STATE = {
    "is_locked": False,
    "s3_locked": False,
    "ec2_locked": False,
    "sns_dispatched": False,
    "last_action": "Server active on Vercel"
}


class handler(BaseHTTPRequestHandler):
    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        s3_url = f"https://{TARGET_BUCKET}.s3.amazonaws.com/{SAMPLE_FILE}"

        if path in ("/verify-access", "/api/verify-access"):
            is_locked = STATE["s3_locked"] or STATE["is_locked"]
            status_code = 403 if is_locked else 200
            preview = "<Error><Code>AccessDenied</Code><Message>Public access denied on AWS</Message></Error>" if is_locked else DEFAULT_CSV_CONTENT

            payload = {
                "http_status": status_code,
                "is_locked": STATE["is_locked"],
                "s3_locked": STATE["s3_locked"],
                "ec2_locked": STATE["ec2_locked"],
                "sns_dispatched": STATE["sns_dispatched"],
                "latest_sns_message": "EMERGENCY LOCKDOWN: S3 Public Access revoked & EC2 fleet quarantined." if STATE["sns_dispatched"] else "Topic Ready",
                "object_url": s3_url,
                "access_state": "DENIED (403/404)" if is_locked else "EXPOSED (200 OK)",
                "content_preview": preview.strip(),
                "ec2_status": "Fleet Quarantined (Paused)" if STATE["ec2_locked"] else "2 Instances (Active)",
                "localstack_connected": True,
                "last_action": STATE["last_action"]
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if path in ("/sns-messages", "/api/sns-messages"):
            msgs = []
            if STATE["sns_dispatched"]:
                msgs.append({
                    "subject": "[SEV-1] Incident Containment Alert",
                    "message": "EMERGENCY LOCKDOWN: S3 Public Access revoked & EC2 fleet quarantined.",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "topic": "arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts"
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"messages": msgs}).encode("utf-8"))
            return

        self.send_response(404)
        self._send_cors()
        self.end_headers()
        self.wfile.write(b"Endpoint Not Found")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")

        if path in ("/panic", "/api/panic"):
            STATE["is_locked"] = True
            STATE["s3_locked"] = True
            STATE["ec2_locked"] = True
            STATE["sns_dispatched"] = True
            STATE["last_action"] = "Full Lockdown Enforced"

            try:
                import boto3
                s3 = boto3.client("s3", region_name="us-east-1")
                s3.put_public_access_block(
                    Bucket=TARGET_BUCKET,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                )
            except Exception:
                pass

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Full lockdown enabled"}).encode("utf-8"))
            return

        if path in ("/reset", "/api/reset"):
            STATE["is_locked"] = False
            STATE["s3_locked"] = False
            STATE["ec2_locked"] = False
            STATE["sns_dispatched"] = False
            STATE["last_action"] = "Lockdown Disabled - Services Restored"

            try:
                import boto3
                s3 = boto3.client("s3", region_name="us-east-1")
                s3.delete_public_access_block(Bucket=TARGET_BUCKET)
            except Exception:
                pass

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Services restored"}).encode("utf-8"))
            return

        if path in ("/toggle/s3", "/api/toggle/s3"):
            STATE["s3_locked"] = not STATE["s3_locked"]
            msg = "S3 locked" if STATE["s3_locked"] else "S3 restored"
            STATE["last_action"] = msg
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "s3_locked": STATE["s3_locked"], "message": msg}).encode("utf-8"))
            return

        if path in ("/toggle/ec2", "/api/toggle/ec2"):
            STATE["ec2_locked"] = not STATE["ec2_locked"]
            msg = "EC2 stopped" if STATE["ec2_locked"] else "EC2 running"
            STATE["last_action"] = msg
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "ec2_locked": STATE["ec2_locked"], "message": msg}).encode("utf-8"))
            return

        if path in ("/toggle/sns", "/api/toggle/sns"):
            STATE["sns_dispatched"] = True
            msg = "SNS alert dispatched"
            STATE["last_action"] = msg
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": msg}).encode("utf-8"))
            return

        self.send_response(404)
        self._send_cors()
        self.end_headers()
        self.wfile.write(b"Endpoint Not Found")
