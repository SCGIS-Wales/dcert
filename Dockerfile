# syntax=docker/dockerfile:1.7

############################
# Builder
############################
FROM rust:1.81-alpine AS builder
WORKDIR /app

# Build deps needed for static-ish binaries
RUN apk add --no-cache musl-dev

# Copy manifest only, generate lockfile if missing
COPY Cargo.toml ./
# Always ensure a lockfile exists so subsequent steps are stable
RUN cargo generate-lockfile

# Prime dependency cache with a dummy main, then build once
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
# Clean placeholder sources to avoid stale code
RUN rm -rf src

# Copy the actual project sources
# If your repo includes a Cargo.lock, this will overwrite the generated one
COPY . .

# Build your binary
RUN cargo build --release

############################
# Runtime
############################
FROM alpine:3.18 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/dcert /usr/local/bin/dcert
ENTRYPOINT ["/usr/local/bin/dcert"]
