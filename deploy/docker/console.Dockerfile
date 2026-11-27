# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@12.9.1 --activate
COPY --parents package.json pnpm-lock.yaml pnpm-workspace.yaml apps/console/package.json packages/*/package.json ./
RUN pnpm install --frozen-lockfile --filter console...
COPY --parents apps/console packages ./
RUN pnpm --filter console build && rm -f apps/console/dist/config.json

FROM nginx:stable-alpine
RUN apk add --no-cache ca-certificates curl jq \
    && mkdir -p /run/identity-console \
    && chown nginx:nginx /run/identity-console
COPY deploy/docker/console/nginx.conf.template deploy/docker/console/console-config.js /etc/nginx/
COPY --chmod=755 deploy/docker/console/entrypoint.sh /usr/local/bin/console-entrypoint
COPY --from=builder /app/apps/console/dist/ /usr/share/nginx/html/console/
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s \
    CMD curl --fail --silent http://127.0.0.1:8081/health || exit 1
ENTRYPOINT ["/usr/local/bin/console-entrypoint"]
CMD ["nginx", "-c", "/run/identity-console/nginx.conf", "-g", "daemon off;"]
