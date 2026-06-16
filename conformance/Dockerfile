FROM node:22-slim AS ui-builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@latest
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
COPY ui/auth/ ui/auth/
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @identity/auth-ui build

FROM rust:1.96-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=ui-builder /app/assets/static /app/assets/static
COPY --from=ui-builder /app/assets/views /app/assets/views
RUN cargo build --release --bin identity --features oidc-conformance

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/identity /usr/local/bin/identity
COPY --from=builder /app/assets /app/assets
COPY --from=builder /app/config /app/config
WORKDIR /app
CMD ["identity"]
