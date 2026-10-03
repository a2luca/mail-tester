FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml src/ ./
RUN pip install --no-cache-dir --no-warn-script-location --prefix=/install .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="mailtest" \
      org.opencontainers.image.description="Auto-responder that replies with an SPF/DKIM/DMARC report" \
      org.opencontainers.image.source="https://github.com/llwn/mailtest" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1000 app \
 && mkdir /data && chown app /data

COPY --from=builder /install /usr/local

VOLUME /data
USER app
ENTRYPOINT ["mailtest"]
