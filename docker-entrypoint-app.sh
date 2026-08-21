#!/bin/sh
set -e

# The cert is generated once by the cert-init service into a shared
# volume, not by each replica -- if every replica minted its own
# self-signed cert independently, different replicas would present
# different certs to the same client across reconnects.
for i in $(seq 1 40); do
  [ -f "$QAD_CERT_FILE" ] && break
  echo "waiting for shared TLS cert at $QAD_CERT_FILE ($i/40)"
  sleep 0.5
done
if [ ! -f "$QAD_CERT_FILE" ]; then
  echo "TLS cert never appeared -- did cert-init run?" >&2
  exit 1
fi

for i in $(seq 1 40); do
  [ -S "$QAD_KMS_SOCKET" ] && break
  echo "waiting for KMS socket at $QAD_KMS_SOCKET ($i/40)"
  sleep 0.5
done
if [ ! -S "$QAD_KMS_SOCKET" ]; then
  echo "KMS socket never appeared -- is the kms service healthy?" >&2
  exit 1
fi

cd /app/server
exec uvicorn main:app \
  --host "$QAD_HOST" --port "$QAD_PORT" \
  --ssl-certfile "$QAD_CERT_FILE" --ssl-keyfile "$QAD_KEY_FILE"
