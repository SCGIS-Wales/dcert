# syntax=docker/dockerfile:1.7

############################
# Builder
############################
FROM rust:1-alpine AS builder
WORKDIR /app

# Install build dependencies for musl targets and OpenSSL
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

# Copy manifest and generate lockfile for dependency caching
COPY Cargo.toml ./
RUN cargo generate-lockfile

# Create dummy sources to prebuild dependencies
RUN mkdir -p src src/mcp && echo 'fn main() {}' > src/main.rs && echo 'fn main() {}' > src/mcp/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy full source and rebuild with actual code
COPY . .
RUN cargo build --release

############################
# Runtime
############################
FROM alpine:3.23 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/dcert /usr/local/bin/dcert
COPY --from=builder /app/target/release/dcert-mcp /usr/local/bin/dcert-mcp

ENTRYPOINT ["/usr/local/bin/dcert"]
