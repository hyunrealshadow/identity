# syntax=docker/dockerfile:1
FROM rust:1.100-bookworm AS builder
WORKDIR /app

COPY --from=node:22-bookworm-slim --parents /usr/local/bin/node /usr/local/lib/node_modules/corepack /
RUN ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && corepack enable && corepack prepare pnpm@12.9.1 --activate \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build:error-css \
    && cargo build --locked --release --bin identity

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home identity
WORKDIR /app
COPY --from=builder /app/target/release/identity /usr/local/bin/identity
COPY --from=builder /app/assets /app/assets
RUN mkdir -p /app/config /tmp/identity && chown -R identity:identity /app /tmp/identity
USER 10001:10001
EXPOSE 5150 5151 8081
CMD ["identity"]
