# syntax=docker/dockerfile:1

# --- Build stage ---------------------------------------------------------
# go-sqlite3 (CGO) is part of the binary even when running against Postgres,
# so CGO must stay enabled for the build to succeed.
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/rocketvault .

# --- Runtime stage --------------------------------------------------------
# debian-slim (not distroless/scratch) because the binary is CGO-linked
# against glibc and go-sqlite3 needs libc at runtime.
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget gettext-base \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /home/rocketvault --shell /usr/sbin/nologin rocketvault

WORKDIR /app

COPY --from=build /out/rocketvault /app/rocketvault

# Default config for plain "docker run" usage (SQLite, matches local dev).
# docker-compose.yml overrides this by bind-mounting the Postgres template
# below plus docker-entrypoint.sh, which renders it before the binary starts.
COPY .rocketvault.yaml /app/.rocketvault.yaml
COPY .rocketvault.docker.yaml.tmpl /app/.rocketvault.docker.yaml.tmpl
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

RUN mkdir -p /app/data /app/logs && chown -R rocketvault:rocketvault /app

USER rocketvault

EXPOSE 8774

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8774/api/v1/health/live || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/rocketvault", "serve"]
