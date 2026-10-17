FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright \
    PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /root/.cache/uv

COPY *.py ./
COPY scripts/*.py scripts/
COPY tests/*.py tests/
ENTRYPOINT ["python"]
CMD ["run.py", "--no-docker"]
