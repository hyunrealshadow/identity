FROM rust:1.88-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --bin identity --features oidc-conformance

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/identity /usr/local/bin/identity
COPY --from=builder /app/assets /app/assets
COPY --from=builder /app/config /app/config
WORKDIR /app
CMD ["identity"]
