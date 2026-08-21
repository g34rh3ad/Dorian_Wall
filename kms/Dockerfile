FROM python:3.13-slim

WORKDIR /app
COPY kms/kms_daemon.py .

RUN useradd --create-home --shell /usr/sbin/nologin kms && \
    mkdir -p /data/kms /run/kms && \
    chown -R kms:kms /data/kms /run/kms
USER kms

ENV QAD_KMS_HOME=/data/kms

ENTRYPOINT ["python3", "kms_daemon.py", "/run/kms/kms.sock"]
