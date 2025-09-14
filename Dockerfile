# syntax=docker/dockerfile:1.7

############################
# Builder
############################
FROM rust:1.89-alpine3.22 AS builder
WORKDIR /app

# Install build dependencies for musl targets and OpenSSL
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

# Copy manifest and ensure lockfile exists for reproducible builds
COPY Cargo.toml ./
RUN cargo generate-lockfile

# Create dummy main.rs to prebuild dependencies
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy full source and rebuild with actual code
COPY . .
RUN cargo build --release

############################
# Runtime
############################
FROM alpine:3.18 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/dcert /usr/local/bin/dcert

ENTRYPOINT ["/usr/local/bin/dcert"]
