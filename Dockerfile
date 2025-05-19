FROM ghcr.io/astral-sh/uv:python3.13-bookworm

COPY . /app

WORKDIR /app

ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync

CMD ["uv", "run", "gunicorn", "-b", "0.0.0.0", "main:app"]
