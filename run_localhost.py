#!/usr/bin/env python3
"""
ScamShield AI - Interactive Localhost Launcher & Network Hub
Provides easy 1-click startup, LAN access IP detection, free port discovery,
browser auto-launching, and Cloudflare Tunnel integration.
"""

import os
import sys
import socket
import subprocess
import time
import webbrowser

# Ensure UTF-8 output encoding for Windows command line console compatibility
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass


def find_free_port(start_port=5000, max_attempts=20):
    """Finds an open TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue
    return start_port

def get_lan_ip():
    """Detects local IPv4 network address for LAN sharing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def print_banner(port, lan_ip, tunnel_active=False, tunnel_url=""):
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
====================================================================
           🛡️  SCAMSHIELD AI - LOCALHOST CONTROL CENTER 🛡️
====================================================================

  [SERVER STATUS] : 🟢 ONLINE & BROADCASTING
  [HOST MACHINE]  : {socket.gethostname()}
  [ACTIVE PORT]   : {port}

  ------------------------------------------------------------------
  🌐 LOCAL ACCESS (This Computer):
     👉  http://localhost:{port}
     👉  http://127.0.0.1:{port}

  📱 LAN / WI-FI ACCESS (Other PCs, Phones, Tablets on same Wi-Fi):
     👉  http://{lan_ip}:{port}
  ------------------------------------------------------------------
"""
    if tunnel_active and tunnel_url:
        banner += f"""
  🚀 PUBLIC CLOUDFLARE TUNNEL (Global Access):
     👉  {tunnel_url}
  ------------------------------------------------------------------
"""
    banner += """
  💡 TIPS FOR EASY ACCESS:
     • Open http://localhost:{port} in your browser (Opening now...)
     • Scan the Mobile QR Code on the dashboard to test on your phone!
     • Press Ctrl+C in this terminal window to stop the server cleanly.
====================================================================
""".format(port=port)
    print(banner)

def launch_server():
    preferred_port = int(os.environ.get("PORT", 5000))
    port = find_free_port(preferred_port)
    os.environ["PORT"] = str(port)
    lan_ip = get_lan_ip()

    print_banner(port, lan_ip)

    # Automatically open default browser to Smart Localhost Command Portal
    localhost_portal_url = f"http://127.0.0.1:{port}/localhost"
    print(f"[*] Opening Smart Localhost Portal: {localhost_portal_url} in your browser...")
    try:
        webbrowser.open(localhost_portal_url)
    except Exception as e:

        print(f"[!] Note: Could not auto-launch browser automatically ({e}). Please click the link above.")

    # Execute app.py
    cmd = [sys.executable, "app.py"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n\n[🛡️ ScamShield AI] Server stopped cleanly. Goodbye!")

if __name__ == "__main__":
    launch_server()
