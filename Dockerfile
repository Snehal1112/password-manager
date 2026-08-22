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
    && apt-get install -y --no-install-recommends ca-certificates wget gettext-base gosu softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /home/rocketvault --shell /usr/sbin/nologin rocketvault

WORKDIR /app

COPY --from=build /out/rocketvault /app/rocketvault

# No baked-in .rocketvault.yaml: docker-entrypoint.sh always renders it from
# this template at container startup (see the entrypoint's own header
# comment), parametrized by RV_DB_DRIVER. This is also why .rocketvault.yaml
# is excluded in .dockerignore -- a developer's local copy, with real
# secrets, must never end up in the build context or the image.
COPY .rocketvault.docker.yaml.tmpl /app/.rocketvault.docker.yaml.tmpl
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

RUN mkdir -p /app/data /app/logs && chown -R rocketvault:rocketvault /app

# Fixed regardless of whether RV_HSM_ENABLED is set -- must be a Dockerfile
# ENV, not something docker-entrypoint.sh exports at runtime, so that a
# one-off "docker exec"/"railway ssh" CLI command (e.g. "users admin",
# "backup create") also finds the SoftHSM2 token. Those run as a separate
# process outside the entrypoint's own shell and inherit only the image's
# declared environment, not a sibling shell's runtime exports. Unused and
# harmless when HSM is disabled.
ENV SOFTHSM2_CONF=/app/data/softhsm/softhsm2.conf

# Stays root here -- a platform volume (Railway, Fly) mounts over /app/data
# with root:root ownership at container start, undoing the chown above.
# docker-entrypoint.sh re-chowns whatever landed there and drops to
# rocketvault via gosu before exec'ing the actual server process.
EXPOSE 8774

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8774/api/v1/health/live || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/rocketvault", "serve"]
