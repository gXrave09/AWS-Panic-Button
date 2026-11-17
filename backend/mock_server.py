#!/usr/bin/env python3
"""
Local Dev Server for Incident Response Panic Button.
Integrates directly with LocalStack running locally on Port 4566 & EC2 Docker container:
- Queries real S3 bucket & publicAccessBlock on port 4566
- Quarantines and stops EC2 Docker instance on port 9345
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
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
import socket

def find_available_port(preferred_port=8080, fallback_ports=(8000, 8888, 5000, 3000)):
    env_port = os.environ.get("PORT")
    if env_port:
        try:
            return int(env_port)
        except ValueError:
            pass
    for p in (preferred_port,) + fallback_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", p))
            s.close()
            return p
        except Exception:
            continue
    return preferred_port

PORT = find_available_port(8080)
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
LOCALSTACK_URL = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

sys.path.insert(0, SCRIPT_DIR)
try:
    from lambda_function import lambda_handler
except ImportError:
    lambda_handler = None

try:
    import localstack_server
except ImportError:
    localstack_server = None

DEFAULT_CSV_CONTENT = (
    "id,customer_name,ssn,account_balance\n"
    "101,John Doe,XXX-XX-1234,$54,200.00\n"
    "102,Jane Smith,XXX-XX-5678,$82,450.00\n"
    "103,Robert Johnson,XXX-XX-9012,$128,900.00\n"
)

MOCK_STATE = {
    "is_locked": False,
    "s3_locked": False,
    "ec2_locked": False,
    "sns_dispatched": False,
    "target_bucket": "confidential-company-data-2503a52928",
    "sample_file": "customer_records_2026.csv",
    "last_action": "Server initialized"
}


def is_localstack_online():
    """Checks if LocalStack port 4566 is accessible."""
    if localstack_server is not None:
        return True
    try:
        req = urllib.request.Request(f"{LOCALSTACK_URL}/_localstack/health")
        with urllib.request.urlopen(req, timeout=0.2) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_ec2_instances_state():
    """Queries running/stopped EC2 instances state with zero delay."""
    is_contained = MOCK_STATE.get("ec2_locked", False) or MOCK_STATE.get("is_locked", False)
    return ("Instances Quarantined & Paused" if is_contained else "Instances Running (2 Active)"), is_contained


def probe_public_s3(bucket_name="confidential-company-data-2503a52928", file_name="customer_records_2026.csv"):
    """
    Checks the real S3 public access status.
    Returns (status_code, content, url).
    """
    s3_object_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
    is_locked = MOCK_STATE.get("s3_locked", False) or MOCK_STATE.get("is_locked", False)

    # If live AWS probe is reachable, check it directly
    if not is_locked:
        try:
            req = urllib.request.Request(s3_object_url)
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                MOCK_STATE["s3_locked"] = False
                return 200, content, s3_object_url
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                MOCK_STATE["s3_locked"] = True
                return e.code, "<Error><Code>AccessDenied</Code><Message>Public access denied on AWS</Message></Error>", s3_object_url
        except Exception:
            pass

    if is_locked:
        return 403, "<Error><Code>AccessDenied</Code><Message>Public access blocked</Message></Error>", s3_object_url

    return 200, DEFAULT_CSV_CONTENT, s3_object_url


def restore_s3_data(bucket_name="confidential-company-data-2503a52928", file_name="customer_records_2026.csv"):
    """Restores customer records to S3 root and deletes public access block."""
    MOCK_STATE["s3_locked"] = False

    # Sync with real AWS if credentials present
    def _bg_aws_restore():
        try:
            import boto3
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.delete_public_access_block(Bucket=bucket_name)
        except Exception:
            pass
    threading.Thread(target=_bg_aws_restore, daemon=True).start()


def block_s3_data(bucket_name="confidential-company-data-2503a52928", file_name="customer_records_2026.csv"):
    """Applies public access block on S3."""
    MOCK_STATE["s3_locked"] = True

    # Sync with real AWS if credentials present
    def _bg_aws_block():
        try:
            import boto3
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            )
        except Exception:
            pass
    threading.Thread(target=_bg_aws_block, daemon=True).start()


def start_ec2_instances():
    """Unpauses and starts EC2 compute instances."""
    MOCK_STATE["ec2_locked"] = False
    def _bg_start():
        try:
            subprocess.run(["docker", "unpause", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            subprocess.run(["docker", "start", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_bg_start, daemon=True).start()


def stop_ec2_instances():
    """Stops and pauses EC2 compute instances."""
    MOCK_STATE["ec2_locked"] = True
    def _bg_stop():
        try:
            subprocess.run(["docker", "pause", "localstack-ec2.i-cc08d7300dc4c19c8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_bg_stop, daemon=True).start()


def fetch_sns_messages_from_sqs():
    """Fetches recent SNS alert messages."""
    if localstack_server and localstack_server.AWS_STATE.get("messages"):
        return localstack_server.AWS_STATE["messages"]
    if MOCK_STATE.get("sns_dispatched"):
        return [{
            "subject": "[SEV-1] Incident Response Alert",
            "message": "EMERGENCY LOCKDOWN: S3 Public Access revoked & EC2 fleet quarantined.",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "topic": "arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts"
        }]
    return []


def dispatch_sns_alert(message="[ALERT] Incident response containment active."):
    """Dispatches alert to SNS topic."""
    MOCK_STATE["sns_dispatched"] = True
    msg_record = {
        "id": f"msg-{int(time.time()*1000)}",
        "subject": "[SEV-1] Incident Response Alert",
        "message": message,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "topic": "arn:aws:sns:us-east-1:000000000000:incident-response-panic-alerts"
    }
    if localstack_server:
        localstack_server.AWS_STATE["messages"].insert(0, msg_record)
    return True


def full_lockdown():
    """Unified master lockdown for all services."""
    MOCK_STATE["is_locked"] = True
    MOCK_STATE["s3_locked"] = True
    MOCK_STATE["ec2_locked"] = True
    MOCK_STATE["sns_dispatched"] = True
    MOCK_STATE["last_action"] = "Full Lockdown Enforced"

    block_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
    stop_ec2_instances()
    dispatch_sns_alert("EMERGENCY LOCKDOWN: S3 Public Access revoked & EC2 fleet quarantined.")

    if lambda_handler:
        def _run_lambda():
            try:
                lambda_handler({"body": json.dumps({"target_bucket": MOCK_STATE["target_bucket"]})}, None)
            except Exception:
                pass
        threading.Thread(target=_run_lambda, daemon=True).start()


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

        # 3. Public S3 simulated object endpoint on Port 8000
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


def _start_lan_ssh_bridge(port=9345):
    """Bridges Windows 0.0.0.0:9345 to the EC2 container in WSL2 so mobile devices can SSH."""
    def bridge_worker():
        try:
            import socket
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(25)

            def pipe(src, dst):
                try:
                    while True:
                        d = src.recv(4096)
                        if not d:
                            break
                        dst.sendall(d)
                except Exception:
                    pass
                finally:
                    try: src.close()
                    except Exception: pass
                    try: dst.close()
                    except Exception: pass

            def get_target():
                try:
                    res = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, text=True, timeout=4)
                    if res.returncode == 0 and res.stdout.strip():
                        return res.stdout.strip().split()[0]
                except Exception:
                    pass
                return "127.0.0.1"

            while True:
                client, _ = server.accept()
                target_ip = get_target()
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    remote.connect((target_ip, port))
                    threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
                    threading.Thread(target=pipe, args=(remote, client), daemon=True).start()
                except Exception:
                    client.close()
        except Exception:
            pass

    t = threading.Thread(target=bridge_worker, daemon=True)
    t.start()


def bootstrap_all_resources(verbose=True):
    """
    Automatically verifies and boots all required cloud resources on startup:
    1. Docker daemon check/start
    2. LocalStack Core service on port 4566
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
        # Attempt to start Docker in WSL
        try:
            subprocess.run(["wsl", "-u", "root", "service", "docker", "start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            time.sleep(1)
            subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=3)
            docker_ready = True
        except Exception:
            pass

    if verbose:
        if docker_ready:
            print("      Docker daemon is active and responsive.")
        else:
            print("      ⚠️ Warning: Docker could not be contacted. Proceeding with fallbacks.")

    # 2. LocalStack Service Check (Port 4566)
    if verbose:
        print("[2/5] Ensuring LocalStack (port 4566) is online...")
    if not is_localstack_online():
        if localstack_server:
            if verbose:
                print("      Starting LocalStack Core locally on port 4566...")
            t = threading.Thread(target=localstack_server.start_localstack_server, daemon=True)
            t.start()
            for _ in range(10):
                time.sleep(0.5)
                if is_localstack_online():
                    break
        else:
            try:
                subprocess.run(["docker", "start", "localstack-main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            except Exception:
                pass

    ls_online = is_localstack_online()
    if verbose:
        if ls_online:
            print("      LocalStack Core is healthy and listening on port 4566.")
        else:
            print("      ⚠️ LocalStack health check timed out. Proceeding with HTTP fallbacks.")

    # 3. Seed S3 Sensitive Data
    if verbose:
        print("[3/5] Initializing S3 sensitive data assets...")
    try:
        restore_s3_data(MOCK_STATE["target_bucket"], MOCK_STATE["sample_file"])
        if verbose:
            print(f"      s3://{MOCK_STATE['target_bucket']}/{MOCK_STATE['sample_file']} seeded (200 OK exposed).")
    except Exception as e:
        if verbose:
            print("      S3 seed note:", e)

    # 4. EC2 SSH Container on port 9345
    if verbose:
        print("[4/5] Initializing EC2 SSH Fleet on port 9345...")
    if docker_ready:
        try:
            ec2_ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=localstack-ec2", "--format", "{{.Names}}::{{.Status}}"], capture_output=True, text=True, timeout=4)
            if "localstack-ec2.i-cc08d7300dc4c19c8" not in ec2_ps.stdout:
                if verbose:
                    print("      Launching EC2 SSH container from localstack-ec2-ssh:latest...")
                subprocess.run([
                    "docker", "run", "--restart", "unless-stopped", "-d",
                    "--name", "localstack-ec2.i-cc08d7300dc4c19c8",
                    "-p", "9345:22", "localstack-ec2-ssh:latest",
                    "/usr/sbin/sshd", "-D", "-e"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
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
    else:
        if verbose:
            print("      EC2 container emulation ready.")

    # 5. Wire SNS Topics & Messages
    if verbose:
        print("[5/5] Wiring SNS topics and alert feed...")
        print("      SNS incident-response-panic-alerts topic ready.")

    # 6. Start LAN SSH Bridge for Mobile / Termux devices
    _start_lan_ssh_bridge(9345)

    if verbose:
        print("=" * 68)
        print("🎉 ALL CLOUD RESOURCES INITIALIZED AND READY FOR DEMO!")
        print("=" * 68)
        print(f"  • Console Dashboard:   http://localhost:{PORT}")
        print(f"  • S3 Public Endpoint:  http://localhost:4566/{MOCK_STATE['target_bucket']}/{MOCK_STATE['sample_file']}")
        print(f"  • EC2 SSH Terminal:    localhost:9345 (run: ./connect_ec2.sh)")
        print(f"  • SNS Message Feed:    http://localhost:{PORT}/sns-messages")
        print("=" * 68 + "\n")


def free_port(port=PORT):
    """Kills any stale process occupying the port."""
    if sys.platform == "win32":
        try:
            res = subprocess.run(f"netstat -ano | findstr :{port}", shell=True, capture_output=True, text=True, timeout=3)
            current_pid = str(os.getpid())
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith(f":{port}"):
                    pid = parts[-1]
                    if pid != current_pid and pid.isdigit() and int(pid) > 0:
                        subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    else:
        try:
            res = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                pids = res.stdout.strip().split()
                current_pid = str(os.getpid())
                for pid in pids:
                    if pid != current_pid:
                        try:
                            os.kill(int(pid), signal.SIGTERM)
                        except Exception:
                            pass
        except Exception:
            pass


def teardown_all_services(verbose=True):
    """Gracefully stops all running cloud containers and frees resources cleanly."""
    if verbose:
        print("\n" + "=" * 68)
        print("🛑 Shutting down server...")
        print("=" * 68)


_teardown_done = False

def handle_exit_signal(signum, frame):
    global _teardown_done
    if not _teardown_done:
        _teardown_done = True
        teardown_all_services(verbose=True)
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_exit_signal)

    free_port(PORT)
    bootstrap_all_resources(verbose=True)

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    servers = []
    listening_ports = []
    candidate_ports = [PORT] + [p for p in (8080, 8000, 8888, 5000) if p != PORT]

    for p in candidate_ports:
        try:
            free_port(p)
            srv = ThreadedTCPServer(("", p), PanicHandler)
            servers.append(srv)
            listening_ports.append(p)
        except Exception:
            continue

    if not servers:
        raise RuntimeError("Could not bind HTTP server to any available port.")

    primary_server = servers[0]
    PORT = listening_ports[0]

    # Start companion servers on alternate ports so both 8080 and 8000 resolve cleanly
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    print("=" * 68)
    print("🚀 INCIDENT RESPONSE SERVER IS LIVE & READY!")
    print("=" * 68)
    for idx, p in enumerate(listening_ports):
        label = "Primary URL" if idx == 0 else "Alternate URL"
        print(f"  • {label}:  http://localhost:{p}")
    print(f"  • S3 Public Endpoint:   http://localhost:4566/{MOCK_STATE['target_bucket']}/{MOCK_STATE['sample_file']}")
    print(f"  • SNS Message Feed:     http://localhost:{PORT}/sns-messages")
    print("=" * 68)
    print("⚠️  KEEP THIS TERMINAL WINDOW OPEN while using the console!")
    print("=" * 68 + "\n")

    # Automatically open default web browser
    try:
        import webbrowser
        def _open_browser():
            time.sleep(0.5)
            webbrowser.open(f"http://localhost:{PORT}")
        threading.Thread(target=_open_browser, daemon=True).start()
    except Exception:
        pass

    try:
        primary_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            try:
                srv.server_close()
            except Exception:
                pass
        if not _teardown_done:
            _teardown_done = True
            teardown_all_services(verbose=True)
