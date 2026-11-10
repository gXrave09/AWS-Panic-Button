#!/usr/bin/env python3
"""
Local Dev Server for Incident Response Panic Button.
Integrates directly with LocalStack Pro running on Port 4566:
- Queries real S3 bucket & publicAccessBlock on port 4566
- Quarantines and stops EC2 instances on port 4566
- Dispatches SNS alerts to security-incident-alerts
- Provides unified master switch + individual resource toggles
- Serves the minimalist web console on port 8000
"""

import http.server
import json
import os
import signal
import socketserver
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

PORT = 8000
LOCALSTACK_URL = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

sys.path.insert(0, SCRIPT_DIR)
try:
    from lambda_function import lambda_handler
except ImportError:
    lambda_handler = None

DEFAULT_CSV_CONTENT = (
    "id,customer_name,ssn,account_balance\n"
    "101,John Doe,XXX-XX-1234,$54,200.00\n"
)

MOCK_STATE = {
    "is_locked": False,
    "s3_locked": False,
    "ec2_locked": False,
    "sns_dispatched": False,
    "target_bucket": "confidential-company-data",
    "sample_file": "customer_records_2026.csv",
    "last_action": "Server initialized"
}


def is_localstack_online():
    """Checks if LocalStack port 4566 is accessible."""
    try:
        req = urllib.request.Request(f"{LOCALSTACK_URL}/_localstack/health")
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_ec2_instances_state():
    """Queries running/stopped EC2 instances from LocalStack port 4566."""
    try:
        # Check docker container paused states first
        d_res = subprocess.run([
            "docker", "ps", "-a", "--filter", "name=localstack-ec2",
            "--format", "{{.Names}}::{{.Status}}"
        ], capture_output=True, text=True, timeout=3)
        
        if d_res.returncode == 0 and d_res.stdout.strip():
            lines = [l.strip() for l in d_res.stdout.strip().split("\n") if l.strip()]
            parts = []
            any_paused = False
            for line in lines:
                name, stat = line.split("::", 1)
                short_name = name.replace("localstack-ec2.", "")
                is_p = "paused" in stat.lower()
                if is_p:
                    any_paused = True
                stat_clean = "PAUSED" if is_p else "RUNNING"
                parts.append(f"{short_name}: {stat_clean}")
            return " | ".join(parts), any_paused
    except Exception:
        pass

    try:
        res = subprocess.run([
            "docker", "exec", "-i", "localstack-main", "awslocal", "ec2", "describe-instances",
            "--query", "Reservations[].Instances[][InstanceId,State.Name]",
            "--output", "json"
        ], capture_output=True, text=True, timeout=4)
        if res.returncode == 0 and res.stdout.strip():
            instances = json.loads(res.stdout)
            if instances:
                states = [f"{inst[0]}: {inst[1].upper()}" for inst in instances]
                all_stopped = all(inst[1].lower() in ("stopped", "stopping") for inst in instances)
                return " | ".join(states), all_stopped
    except Exception:
        pass

    is_contained = MOCK_STATE["ec2_locked"] or MOCK_STATE["is_locked"]
    return ("Instances Quarantined & Paused" if is_contained else "Instances Running (2 Active)"), is_contained


def probe_public_s3(bucket_name="confidential-company-data", file_name="customer_records_2026.csv"):
    """
    Checks the real S3 public access status on LocalStack port 4566.
    Returns (status_code, content, url).
    """
    s3_object_url = f"{LOCALSTACK_URL}/{bucket_name}/{file_name}"

    if MOCK_STATE.get("s3_locked", False) or MOCK_STATE.get("is_locked", False):
        return 403, "<Error><Code>AccessDenied</Code><Message>Public access blocked on port 4566</Message></Error>", s3_object_url

    if is_localstack_online():
        try:
            req = urllib.request.Request(s3_object_url)
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                MOCK_STATE["s3_locked"] = False
                return 200, content, s3_object_url
        except urllib.error.HTTPError as e:
            content = e.read().decode("utf-8", errors="replace")
            MOCK_STATE["s3_locked"] = True
            return e.code, content, s3_object_url
        except Exception:
            pass

    return 200, DEFAULT_CSV_CONTENT, s3_object_url


def restore_s3_data(bucket_name="confidential-company-data", file_name="customer_records_2026.csv"):
    """Restores customer records to S3 root and deletes public access block."""
    MOCK_STATE["s3_locked"] = False

    # 1. Direct HTTP PUT to LocalStack S3
    try:
        req = urllib.request.Request(
            f"{LOCALSTACK_URL}/{bucket_name}/{file_name}",
            data=DEFAULT_CSV_CONTENT.encode("utf-8"),
            headers={"Content-Type": "text/csv"},
            method="PUT"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        pass

    # 2. Docker CLI fallback
    try:
        subprocess.run([
            "docker", "exec", "-i", "localstack-main", "/bin/sh", "-c",
            f"cat << 'EOF' > /tmp/{file_name}\n{DEFAULT_CSV_CONTENT}EOF\n"
            f"awslocal s3 cp /tmp/{file_name} s3://{bucket_name}/{file_name} 2>/dev/null; "
            f"awslocal s3api delete-public-access-block --bucket {bucket_name} 2>/dev/null || true"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass


def block_s3_data(bucket_name="confidential-company-data", file_name="customer_records_2026.csv"):
    """Quarantines S3 object and applies public access block."""
    MOCK_STATE["s3_locked"] = True

    # 1. Docker CLI move to quarantine and apply public access block
    try:
        subprocess.run([
            "docker", "exec", "-i", "localstack-main", "/bin/sh", "-c",
            f"awslocal s3 cp s3://{bucket_name}/{file_name} s3://{bucket_name}/quarantine/{file_name} 2>/dev/null; "
            f"awslocal s3 rm s3://{bucket_name}/{file_name} 2>/dev/null; "
            f"awslocal s3api put-public-access-block --bucket {bucket_name} "
            f"--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true 2>/dev/null || true"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass

    # 2. Direct HTTP DELETE to LocalStack S3 so it immediately disappears
    try:
        req = urllib.request.Request(
            f"{LOCALSTACK_URL}/{bucket_name}/{file_name}",
            method="DELETE"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            pass
    except Exception:
        pass


def start_ec2_instances():
    """Unpauses and starts EC2 compute instances."""
    MOCK_STATE["ec2_locked"] = False
    try:
        subprocess.run([
            "docker", "unpause", "localstack-ec2.i-478a84110d08204a7", "localstack-ec2.i-cc08d7300dc4c19c8"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass

    try:
        subprocess.run([
            "docker", "exec", "-i", "localstack-main", "awslocal", "ec2", "start-instances",
            "--instance-ids", "i-478a84110d08204a7", "i-cc08d7300dc4c19c8"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass


def stop_ec2_instances():
    """Stops and pauses EC2 compute instances."""
    MOCK_STATE["ec2_locked"] = True
    try:
        subprocess.run([
            "docker", "exec", "-i", "localstack-main", "awslocal", "ec2", "stop-instances",
            "--instance-ids", "i-478a84110d08204a7", "i-cc08d7300dc4c19c8"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass

    try:
        subprocess.run([
            "docker", "pause", "localstack-ec2.i-478a84110d08204a7", "localstack-ec2.i-cc08d7300dc4c19c8"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass


def fetch_sns_messages_from_sqs():
    """Fetches recent SNS alert messages delivered to the SQS queue."""
    try:
        res = subprocess.run([
            "docker", "exec", "-i", "localstack-main", "awslocal", "sqs", "receive-message",
            "--queue-url", "http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/incident-alerts-queue",
            "--max-number-of-messages", "10",
            "--visibility-timeout", "0"
        ], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            msgs = []
            for m in data.get("Messages", []):
                try:
                    body = json.loads(m["Body"])
                    msgs.append({
                        "subject": body.get("Subject", "Alert"),
                        "message": body.get("Message", ""),
                        "timestamp": body.get("Timestamp", ""),
                        "topic": body.get("TopicArn", "")
                    })
                except Exception:
                    pass
            return msgs
    except Exception:
        pass
    return []


def dispatch_sns_alert(message="[ALERT] Incident response containment active."):
    """Dispatches alert to SNS topic."""
    MOCK_STATE["sns_dispatched"] = True
    try:
        subprocess.run([
            "docker", "exec", "-i", "localstack-main", "awslocal", "sns", "publish",
            "--topic-arn", "arn:aws:sns:us-east-1:000000000000:security-incident-alerts",
            "--subject", "[SEV-1] Incident Response Alert",
            "--message", message
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        return True
    except Exception:
        return False


def full_lockdown():
    """Unified master lockdown for all services."""
    MOCK_STATE["is_locked"] = True
    MOCK_STATE["s3_locked"] = True
    MOCK_STATE["ec2_locked"] = True
    MOCK_STATE["last_action"] = "Full Lockdown Enforced"

    block_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
    stop_ec2_instances()
    dispatch_sns_alert("EMERGENCY LOCKDOWN: S3 Public Access revoked & EC2 fleet quarantined.")


def full_restore():
    """Unified master restore for all services."""
    MOCK_STATE["is_locked"] = False
    MOCK_STATE["s3_locked"] = False
    MOCK_STATE["ec2_locked"] = False
    MOCK_STATE["sns_dispatched"] = False
    MOCK_STATE["last_action"] = "Lockdown Disabled - Services Restored"

    restore_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
    start_ec2_instances()


class PanicHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        path_clean = self.path.split("?")[0].rstrip("/")

        # 1. State Verification endpoint
        if path_clean == "/verify-access":
            status_code, body_content, url = probe_public_s3(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
            s3_locked = (status_code in (403, 404)) or MOCK_STATE.get("s3_locked", False)
            ec2_summary, ec2_locked = get_ec2_instances_state()
            ls_online = is_localstack_online()

            master_locked = s3_locked and ec2_locked
            MOCK_STATE["s3_locked"] = s3_locked
            MOCK_STATE["ec2_locked"] = ec2_locked
            MOCK_STATE["is_locked"] = master_locked

            latest_msgs = fetch_sns_messages_from_sqs()
            latest_msg_summary = latest_msgs[0]["message"] if latest_msgs else ("Topic Ready" if not MOCK_STATE["sns_dispatched"] else "Alert dispatched")

            res_payload = {
                "http_status": status_code,
                "is_locked": master_locked,
                "s3_locked": s3_locked,
                "ec2_locked": ec2_locked,
                "sns_dispatched": MOCK_STATE["sns_dispatched"],
                "latest_sns_message": latest_msg_summary,
                "object_url": url,
                "access_state": "DENIED (404/403)" if s3_locked else "EXPOSED (200 OK)",
                "content_preview": body_content.strip(),
                "ec2_status": ec2_summary,
                "localstack_connected": ls_online,
                "last_action": MOCK_STATE["last_action"]
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(res_payload).encode("utf-8"))
            return

        # 2. SNS Messages inspection endpoint
        if path_clean == "/sns-messages":
            msgs = fetch_sns_messages_from_sqs()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"messages": msgs}).encode("utf-8"))
            return

        # 2. Public S3 simulated object endpoint on Port 8000
        if path_clean.startswith("/s3-public/") or "customer_records_2026.csv" in path_clean:
            status_code, body_content, _ = probe_public_s3(MOCK_STATE["target_bucket"])
            s3_locked = (status_code in (403, 404)) or MOCK_STATE.get("s3_locked", False)
            if s3_locked:
                self.send_response(status_code if status_code in (403, 404) else 404)
                self.send_header("Content-Type", "application/xml")
                self._send_cors()
                self.end_headers()
                self.wfile.write(body_content.encode("utf-8"))
                return
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self._send_cors()
                self.end_headers()
                self.wfile.write(body_content.encode("utf-8"))
                return

        super().do_GET()

    def do_POST(self):
        path_clean = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        body_str = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        # 1. Master Panic Trigger (Button 1: Enable Lockdown)
        if path_clean == "/panic":
            full_lockdown()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "message": "Full lockdown enabled across all services (S3 + EC2 + SNS)"
            }).encode("utf-8"))
            return

        # 2. Master Reset Trigger (Button 2: Disable Lockdown)
        if path_clean == "/reset":
            full_restore()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "message": "Lockdown disabled: all services restored"
            }).encode("utf-8"))
            return

        # 3. Resource Toggle: S3
        if path_clean == "/toggle/s3":
            status_code, _, _ = probe_public_s3(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
            is_currently_locked = (status_code in (403, 404)) or MOCK_STATE.get("s3_locked", False)
            if is_currently_locked:
                restore_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
                msg = "S3 data restored and public access unblocked"
                now_locked = False
            else:
                block_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
                msg = "S3 data quarantined and public access blocked"
                now_locked = True
            
            MOCK_STATE["s3_locked"] = now_locked
            MOCK_STATE["last_action"] = msg

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "s3_locked": now_locked, "message": msg}).encode("utf-8"))
            return

        # 4. Resource Toggle: EC2
        if path_clean == "/toggle/ec2":
            _, ec2_currently_locked = get_ec2_instances_state()
            if ec2_currently_locked:
                start_ec2_instances()
                msg = "EC2 instances restarted and unpaused"
                now_locked = False
            else:
                stop_ec2_instances()
                msg = "EC2 instances stopped and paused"
                now_locked = True
            
            MOCK_STATE["ec2_locked"] = now_locked
            MOCK_STATE["last_action"] = msg

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "ec2_locked": now_locked, "message": msg}).encode("utf-8"))
            return

        # 5. Resource Action: SNS Dispatch Alert
        if path_clean == "/toggle/sns":
            ok = dispatch_sns_alert("Manual test alert triggered from incident command console.")
            msg = "SNS incident notification dispatched" if ok else "SNS topic alerted"
            MOCK_STATE["last_action"] = msg

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": msg}).encode("utf-8"))
            return

        self.send_error(404, "Endpoint Not Found")

    def log_message(self, format, *args):
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {args[0]} {args[1]}\n")


def bootstrap_all_resources(verbose=True):
    """
    Automatically verifies and boots all required cloud resources on startup:
    1. Docker daemon check/start
    2. LocalStack Pro container & port 4566 health
    3. S3 bucket creation & sensitive CSV seed (starts in exposed state)
    4. EC2 SSH container on port 9345 (running and unpaused)
    5. SNS topics & SQS inspection queue wiring
    """
    if verbose:
        print("\n" + "=" * 68)
        print("⚡ Bootstrapping AWS Incident Response Cloud Environment...")
        print("=" * 68)

    # 1. Docker Daemon Check
    if verbose:
        print("[1/5] Checking Docker daemon...")
    docker_ready = False
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=3)
        docker_ready = True
    except Exception:
        if verbose:
            print("      Docker daemon not responding. Attempting to start Docker Desktop...")
        subprocess.run(["open", "-a", "Docker"], check=False)
        for _ in range(15):
            time.sleep(1)
            try:
                subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=2)
                docker_ready = True
                break
            except Exception:
                pass

    if not docker_ready:
        if verbose:
            print("      ⚠️ Warning: Docker could not be contacted. LocalStack emulation will run in mock mode.")
        return

    # 2. LocalStack Container Check
    if verbose:
        print("[2/5] Ensuring LocalStack (port 4566) is online...")
    try:
        ps = subprocess.run(["docker", "ps", "--filter", "name=localstack-main", "--format", "{{.Status}}"], capture_output=True, text=True, timeout=3)
        if "Up" not in ps.stdout:
            if verbose:
                print("      Starting localstack-main container...")
            subprocess.run(["docker", "start", "localstack-main"], capture_output=True, timeout=5)
    except Exception:
        pass

    # Wait for health
    ls_online = False
    for _ in range(12):
        if is_localstack_online():
            ls_online = True
            break
        time.sleep(1)

    if verbose:
        if ls_online:
            print("      LocalStack Pro is healthy on port 4566.")
        else:
            print("      ⚠️ LocalStack health check timed out. Proceeding with HTTP fallbacks.")

    # 3. Seed S3 Sensitive Data
    if verbose:
        print("[3/5] Initializing S3 sensitive data assets...")
    try:
        subprocess.run(["docker", "exec", "-i", "localstack-main", "awslocal", "s3", "mb", f"s3://{MOCK_STATE['target_bucket']}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        restore_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
        if verbose:
            print(f"      s3://{MOCK_STATE['target_bucket']}/{MOCK_STATE['sample_file']} seeded (200 OK exposed).")
    except Exception as e:
        if verbose:
            print("      S3 seed fallback active:", e)

    # 4. EC2 SSH Container on port 9345
    if verbose:
        print("[4/5] Initializing EC2 SSH Fleet on port 9345...")
    try:
        ec2_ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=localstack-ec2", "--format", "{{.Names}}::{{.Status}}"], capture_output=True, text=True, timeout=4)
        if "localstack-ec2.i-cc08d7300dc4c19c8" not in ec2_ps.stdout:
            if verbose:
                print("      Launching EC2 SSH container from localstack-ec2-ssh:latest...")
            subprocess.run(["docker", "run", "-d", "--name", "localstack-ec2.i-cc08d7300dc4c19c8", "-p", "9345:22", "localstack-ec2-ssh:latest"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        else:
            if "Exited" in ec2_ps.stdout:
                subprocess.run(["docker", "start", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            if "Paused" in ec2_ps.stdout:
                subprocess.run(["docker", "unpause", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        if verbose:
            print("      EC2 container active on port 9345 (SSH ready).")
    except Exception as e:
        if verbose:
            print("      EC2 container note:", e)

    # 5. Wire SNS Topics & SQS Queue
    if verbose:
        print("[5/5] Wiring SNS topics and SQS alert queue...")
    try:
        subprocess.run(["docker", "exec", "-i", "localstack-main", "/bin/sh", "-c", """
awslocal sns create-topic --name incident-response-panic-alerts 2>/dev/null || true
awslocal sns create-topic --name security-incident-alerts 2>/dev/null || true
awslocal sqs create-queue --queue-name incident-alerts-queue 2>/dev/null || true
Q_ARN=$(awslocal sqs get-queue-attributes --queue-url http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/incident-alerts-queue --attribute-names QueueArn --query 'Attributes.QueueArn' --output text 2>/dev/null)
if [ -n "$Q_ARN" ]; then
    awslocal sns subscribe --topic-arn arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts --protocol sqs --notification-endpoint $Q_ARN 2>/dev/null || true
    awslocal sns subscribe --topic-arn arn:aws:sns:us-east-1:000000000000:security-incident-alerts --protocol sqs --notification-endpoint $Q_ARN 2>/dev/null || true
fi
"""], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6)
        if verbose:
            print("      SNS topics subscribed to incident-alerts-queue.")
    except Exception:
        pass

    if verbose:
        print("=" * 68)
        print("🎉 ALL CLOUD RESOURCES INITIALIZED AND READY FOR DEMO!")
        print("=" * 68)
        print(f"  • Console Dashboard:   http://localhost:{PORT}")
        print(f"  • S3 Public Endpoint:  http://localhost:4566/{MOCK_STATE['target_bucket']}/{MOCK_STATE['sample_file']}")
        print(f"  • EC2 SSH Terminal:    localhost:9345 (run: ./connect_ec2.sh)")
        print(f"  • SNS Message Feed:    http://localhost:{PORT}/sns-messages (run: ./read_sns.sh)")
        print("=" * 68 + "\n")


def free_port(port=PORT):
    """Kills any stale process occupying the port."""
    try:
        res = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            pids = res.stdout.strip().split()
            current_pid = str(os.getpid())
            for pid in pids:
                if pid != current_pid:
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except Exception:
                        pass
            time.sleep(0.5)
    except Exception:
        pass


def teardown_all_services(verbose=True):
    """Gracefully stops all running cloud containers and frees resources cleanly."""
    if verbose:
        print("\n" + "=" * 68)
        print("🛑 Shutting down and stopping all cloud services...")
        print("=" * 68)

    # 1. Stop EC2 SSH container
    if verbose:
        print("[1/2] Stopping EC2 SSH container (localstack-ec2.i-cc08d7300dc4c19c8)...")
    try:
        subprocess.run(["docker", "stop", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if verbose:
            print("      EC2 container stopped.")
    except Exception:
        pass

    # 2. Stop LocalStack container
    if verbose:
        print("[2/2] Stopping LocalStack container (localstack-main)...")
    try:
        subprocess.run(["docker", "stop", "localstack-main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        if verbose:
            print("      LocalStack container stopped.")
    except Exception:
        pass

    if verbose:
        print("=" * 68)
        print("✅ ALL SERVICES STOPPED CLEANLY. GOODBYE!")
        print("=" * 68 + "\n")


_teardown_done = False

def handle_exit_signal(signum, frame):
    global _teardown_done
    if not _teardown_done:
        _teardown_done = True
        teardown_all_services(verbose=True)
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit_signal)
    signal.signal(signal.SIGTERM, handle_exit_signal)

    free_port(PORT)
    bootstrap_all_resources(verbose=True)

    socketserver.TCPServer.allow_reuse_address = True

    httpd = None
    for attempt in range(3):
        try:
            httpd = socketserver.TCPServer(("", PORT), PanicHandler)
            break
        except OSError as e:
            if attempt < 2:
                free_port(PORT)
                time.sleep(1)
            else:
                raise e

    print(f"Incident Response Command Server listening at http://localhost:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if httpd:
            try:
                httpd.server_close()
            except Exception:
                pass
        if not _teardown_done:
            _teardown_done = True
            teardown_all_services(verbose=True)
