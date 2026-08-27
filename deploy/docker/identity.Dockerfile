FROM node:22-bookworm-slim AS ui-builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.24.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY assets/styles/ assets/styles/
RUN pnpm install --frozen-lockfile
RUN pnpm build:error-css

FROM rust:1.96-bookworm AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=ui-builder /app/assets/static /app/assets/static
RUN cargo build --locked --release --bin identity

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
