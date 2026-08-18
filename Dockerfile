FROM node:20-slim AS web-builder
WORKDIR /web
COPY web/package.json ./
RUN npm install
COPY web/src ./src
RUN mkdir -p dist && \
    for f in index register login admin; do \
      npx esbuild src/$f.js --bundle --format=esm --target=es2020 --outfile=dist/$f-bundle.js; \
    done && \
    cp src/*.html src/styles.css dist/


FROM python:3.13-slim AS app

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build build-essential git ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV OQS_INSTALL_PATH=/opt/oqs

WORKDIR /app/server
COPY server/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    python3 -c "import oqs; oqs.KeyEncapsulation('ML-KEM-768')"

COPY server/*.py ./
COPY server/routers ./routers
COPY kms /app/kms
COPY --from=web-builder /web/dist /app/web/dist
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

RUN useradd --create-home --shell /usr/sbin/nologin qad && \
    mkdir -p /data/db /data/storage /data/kms /data/certs && \
    chown -R qad:qad /app /data /opt/oqs
USER qad

ENV QAD_HOST=0.0.0.0 \
    QAD_PORT=8443 \
    QAD_DB_PATH=/data/db/drive.db \
    QAD_STORAGE_DIR=/data/storage \
    QAD_STATIC_DIR=/app/web/dist \
    QAD_CERT_FILE=/data/certs/cert.pem \
    QAD_KEY_FILE=/data/certs/key.pem \
    QAD_KMS_HOME=/data/kms \
    QAD_KMS_SOCKET=/data/kms/kms.sock \
    QAD_LOG_JSON=true

EXPOSE 8443
VOLUME ["/data"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
