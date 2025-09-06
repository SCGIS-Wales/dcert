# File: Dockerfile
# Copy to: dcert repository root

# Multi-stage build for optimised container size
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create app directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Touch main.rs to ensure it's rebuilt
RUN touch src/main.rs

# Build the actual application
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:3.18

# Install ca-certificates for TLS verification
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -s /bin/sh -u 1000 -G appuser appuser

# Copy the binary from builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/dcert /usr/local/bin/

# Switch to non-root user
USER appuser

# Set the entrypoint
ENTRYPOINT ["dcert"]

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD dcert --help || exit 1

# Metadata
LABEL org.opencontainers.image.title="dcert - TLS Certificate Decoder"
LABEL org.opencontainers.image.description="A CLI tool to decode and validate TLS certificates from PEM files"
LABEL org.opencontainers.image.vendor="SCGIS Wales"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/SCGIS-Wales/dcert"