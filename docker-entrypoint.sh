#!/bin/sh
set -e

if [ ! -f "$QAD_CERT_FILE" ]; then
  echo "no TLS cert found at $QAD_CERT_FILE -- generating a self-signed one"
  (cd /app/server && python3 gen_cert.py)
fi

python3 /app/kms/kms_daemon.py "$QAD_KMS_SOCKET" &
KMS_PID=$!

trap 'kill -TERM "$KMS_PID" 2>/dev/null' TERM INT

for i in $(seq 1 30); do
  [ -S "$QAD_KMS_SOCKET" ] && break
  sleep 0.5
done
if [ ! -S "$QAD_KMS_SOCKET" ]; then
  echo "KMS did not come up in time" >&2
  exit 1
fi

cd /app/server
exec uvicorn main:app \
  --host "$QAD_HOST" --port "$QAD_PORT" \
  --ssl-certfile "$QAD_CERT_FILE" --ssl-keyfile "$QAD_KEY_FILE"
