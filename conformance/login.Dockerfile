FROM node:22-slim

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/login/package.json apps/login/package.json
RUN pnpm install --frozen-lockfile --filter login...

COPY apps/login apps/login
RUN pnpm --filter login build

EXPOSE 3000

CMD ["pnpm", "--filter", "login", "preview", "--host", "0.0.0.0", "--port", "3000"]
