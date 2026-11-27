# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@12.9.1 --activate
COPY --parents package.json pnpm-lock.yaml pnpm-workspace.yaml apps/login/package.json packages/*/package.json ./
RUN pnpm install --frozen-lockfile --filter login...
COPY --parents apps/login packages ./
RUN pnpm --filter login build
WORKDIR /app/apps/login
USER 1000:1000
EXPOSE 3000
ENV HOST=0.0.0.0 \
    PORT=3000
CMD ["node", "production-server.mjs"]
