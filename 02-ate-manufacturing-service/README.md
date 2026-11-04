# CVE-TBD: Unauthenticated ATE manufacturing service in Tenda FH1201 (`/goform/ate` + UDP 7329)

## Summary

The Tenda FH1201 exposes its factory test (ATE) service without authentication: a single
unauthenticated `GET /goform/ate` starts `/bin/ate`, which then accepts commands on **UDP 7329**.
Those commands include writing nvram values (SSID, WPA key, WPS PIN, MAC, serial number) and the
destructive `Tenda_mfg default`, which restores factory defaults and reboots the device. In addition,
any datagram of 256 bytes or more terminates the daemon.

## Affected Product

- Vendor: Tenda · Product: FH1201 · Firmware: **V1.2.0.19(946)** (latest, 2026-07-13)
- Presumably also ≤ v1.2.0.14(408)
- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published this
  firmware on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Missing Authentication for Critical Function (**CWE-306**), Exposed Dangerous Function
  (**CWE-749**), Uncaught Exception (**CWE-248**)
- Components: `bin/httpd` (`TendaAte()` at `0x0045c25c`) and `bin/ate` (`main()`, `ate_new_interface()`)
- Root cause (1): `/goform/ate` is listed in the exact-match authentication exemption table of
  `authSecurityHandler()`, so the handler runs for anyone:

```c
if (!strcmp(url, "/goform/ate")) { /* unauthenticated */
    doSystemCmd("killall -9 ate");
    doSystemCmd("ate &");            /* starts the manufacturing daemon */
    websWrite(wp, "load mfg success.");
}
```
- Root cause (2): `/bin/ate` implements a plain-text command protocol without any authentication or
  source-address check. Handled verbs observed in the binary:
  `nvram set {mac|boot_wait|pin|SSID|sn}`, `nvram get …`,
  `Tenda_mfg {htmlVersionInfo|default|reboot|check|wlctrl|test|ledtest}`.
  `Tenda_mfg default` executes `cfm Restore`, then `sleep 2 && reboot &`.
- Root cause (3): `main()` returns unconditionally after `ate_new_interface()` fails, and the
  interface parser rejects datagrams whose length is ≥ 256 (boundary verified byte-exactly:
  255 bytes survive, 256 bytes terminate the process with exit code 255).

## Proof of Concept (non-destructive — read-only path shown)

```bash
# start the service (no credentials)
curl -s http://<router>/goform/ate                 # response: "load mfg success."

# read the factory information over UDP (non-destructive)
python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
for cmd in (b"Tenda_mfg htmlVersionInfo", b"nvram get sn", b"Tenda_mfg check"):
    s.sendto(cmd, ("<router>", 7329))
    try: print(cmd, b"->", s.recvfrom(4096)[0][:200])
    except Exception as e: print(cmd, "no reply", e)
PY
```

Verified in the rehosted firmware with `-strace`:

- `execve("/bin/sh", {"sh","-c","killall -9 ate"})` and `execve("/bin/sh", {"sh","-c","ate &"})`
  are executed by the unauthenticated HTTP request;
- `Tenda_mfg default` results in `execve("/bin/sh", {"sh","-c","cfm Restore"})` followed by
  `sleep 2 && reboot &` (destructive; **not** included in the PoC above);
- a 256-byte datagram makes `ate` exit (255 B → alive, 256 B → dead), gdb-single-stepped to the
  `main()` return.

## Impact

- **Unauthenticated factory reset + reboot** of the device (denial of service, loss of configuration).
- **Unauthenticated configuration writes** over UDP: wireless SSID/passphrase, WPS PIN, MAC address,
  serial number — i.e. persistent, attacker-chosen network parameters.
- **Unauthenticated denial of service** of the manufacturing daemon with a single 256-byte packet
  (it is restarted by the next `/goform/ate` request, so the practical impact is limited).
- Related prior art: CVE-2026-82694 (Tenda AC1206) reports the same `/goform/ate` exposure and was
  fixed by removing the endpoint; **FH1201 V1.2.0.19(946) still exposes it**.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` — **8.1**
Rationale: unauthenticated integrity impact (nvram/factory reset) and availability impact (reboot),
scored only for the effects that were dynamically verified.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via firmware rehosting, static analysis, `strace` and gdb
single-stepping of `bin/ate`. Vendor notified: pending.
