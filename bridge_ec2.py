#!/usr/bin/env python3
"""
EC2 Mobile & LAN Network Bridge.
Listens on 0.0.0.0:9345 on Windows and proxies connections to the EC2 container in WSL2.
Allows mobile devices (e.g. Termux on same Wi-Fi) to SSH directly to this PC's Wi-Fi IP.
"""

import socket
import subprocess
import sys
import threading
import time

LOCAL_PORT = 9345
TARGET_PORT = 9345


def get_wsl_ip():
    try:
        res = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, text=True, timeout=4)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().split()[0]
    except Exception:
        pass
    return "127.0.0.1"


def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except Exception: pass
        try: dst.close()
        except Exception: pass


def run_bridge():
    target_ip = get_wsl_ip()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", LOCAL_PORT))
        server.listen(25)
    except Exception as e:
        print(f"Error binding 0.0.0.0:{LOCAL_PORT}: {e}")
        return

    print(f"🚀 EC2 SSH Network Bridge active on 0.0.0.0:{LOCAL_PORT} -> {target_ip}:{TARGET_PORT}")
    print(f"📱 Connect from Termux on your phone using:")
    print(f"   ssh -p {LOCAL_PORT} root@<YOUR_WIFI_IP>")
    print(f"   (Password: root)")

    while True:
        try:
            client, addr = server.accept()
            # Resolve target IP dynamically
            current_target = get_wsl_ip()
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((current_target, TARGET_PORT))
            t1 = threading.Thread(target=forward, args=(client, remote), daemon=True)
            t2 = threading.Thread(target=forward, args=(remote, client), daemon=True)
            t1.start()
            t2.start()
        except Exception as e:
            time.sleep(0.5)


if __name__ == "__main__":
    run_bridge()

