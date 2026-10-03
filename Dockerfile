FROM golang:1.22-alpine AS builder
WORKDIR /build
# Copy every Go source file, not just main.go: the sandbox hardening lives in
# harden.go (portable) plus harden_unix.go / harden_other.go (per-platform).
COPY go.mod ./
COPY main.go harden.go harden_unix.go harden_other.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/service .

FROM eclipse-temurin:21-jdk-alpine@sha256:9ececb44042a7cc91e4e6bca525c678e811c1602330a80b5f2d2fcfa0aa97c4e
LABEL org.opencontainers.image.title="codhoot-java-service"
LABEL org.opencontainers.image.description="Hardened java execution sandbox"
WORKDIR /app
COPY --from=builder /out/service /app/service
RUN chmod 0755 /app/service && rm -f go.mod main.go harden.go harden_unix.go harden_other.go

# --- sandbox identity pool ---------------------------------------------------
# Each in-flight job is dropped to a DISTINCT uid by the service. That is what
# makes a job's 0700 working directory genuinely private: with one shared uid every
# job could read every other job's source and rewrite it before it ran.
# Runtimes that resolve getpwuid (the JVM derives user.name this way) need real
# passwd entries, written directly here rather than with 32 useradd calls.
# shellcheck disable=SC2016
RUN set -eu; \
    i=0; \
    while [ "$i" -lt 32 ]; do \
      u=$((2000 + i)); \
      printf 'codhoot-s%d:x:%d:%d:codhoot sandbox:/nonexistent:/sbin/nologin\n' "$i" "$u" "$u" >> /tmp/pool; \
      i=$((i + 1)); \
    done; \
    cat /tmp/pool >> /etc/passwd; \
    rm -f /tmp/pool; \
    mkdir -p /tmp/codhoot-cache; \
    chmod 0755 /tmp/codhoot-cache

# The service itself runs as root on purpose: it must chown each job directory to
# that job's uid and setuid the compiler/runtime child. The security boundary is
# the child, not the service. Adding `USER runner` here would silently disable
# privilege dropping and leave user code running as root, so it is called out
# rather than left as an apparent oversight.
#
# There is deliberately no HEALTHCHECK here: it would require curl or wget in the
# image, and Render already health-checks /health over HTTP. Adding a network
# client purely for a healthcheck would enlarge the attack surface for no gain.
ENV PORT=8081
EXPOSE 8081
CMD ["/app/service"]
