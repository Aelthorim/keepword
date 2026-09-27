# Witness node container image.
#
#   docker build -t witness .
#   docker run -d --name witness -v witness-data:/data \
#       -p 127.0.0.1:8480:8480 -p 8481:8481 \
#       -e WITNESS_ENDPOINT=https://witness.example.org witness
#
# See packaging/docker/compose.yaml and docs/INSTALL.md for the settings.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Set to "render" for headless-browser capture (also install Chromium below).
ARG FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p witness-node ${FEATURES:+--features $FEATURES} \
    && install -m 0755 target/release/witness /usr/local/bin/witness

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --home-dir /data --shell /usr/sbin/nologin witness \
    && install -d -m 0750 -o witness -g witness /data
COPY --from=build /usr/local/bin/witness /usr/local/bin/witness
COPY packaging/docker/entrypoint.sh /usr/local/bin/witness-entrypoint
USER witness
ENV WITNESS_DIR=/data HOME=/data
VOLUME /data
# 8480: web UI (keep private), 8481: peer API (publish behind TLS)
EXPOSE 8480 8481
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD curl -fsS http://127.0.0.1:8481/v1/descriptor >/dev/null || exit 1
ENTRYPOINT ["witness-entrypoint"]
CMD ["serve", "--addr", "0.0.0.0:8480", "--api-addr", "0.0.0.0:8481", "--watch", "--anchor"]
