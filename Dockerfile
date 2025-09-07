# syntax=docker/dockerfile:1

FROM rust:1-alpine3.22 AS builder
WORKDIR /app
RUN apk add --no-cache musl-dev openssl-dev pkgconfig
COPY Cargo.toml ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && cargo build --release || true
COPY src ./src
COPY build.rs ./
RUN cargo build --release

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/dcert /usr/local/bin/dcert
ENTRYPOINT ["dcert"]
