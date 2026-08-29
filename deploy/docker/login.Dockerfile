FROM node:22-bookworm-slim
ENV COREPACK_HOME=/opt/corepack
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.24.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/login/package.json apps/login/package.json
RUN pnpm install --frozen-lockfile --filter login...
COPY apps/login apps/login
RUN pnpm --filter login build
RUN mkdir -p /app/apps/login/node_modules/.vite-temp \
    && chown node:node /app/apps/login/node_modules/.vite-temp
USER 1000:1000
EXPOSE 3000
ENV HOST=0.0.0.0 \
    PORT=3000
CMD ["pnpm", "--filter", "login", "start"]
