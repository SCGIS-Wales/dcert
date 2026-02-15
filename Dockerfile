# Lightweight Docker image that copies pre-built binaries from CI.
# No Rust compilation — the build-linux job already produces the binaries.
# Uses debian-slim (glibc) since binaries are built with x86_64-unknown-linux-gnu.

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY docker-bin/dcert /usr/local/bin/dcert
COPY docker-bin/dcert-mcp /usr/local/bin/dcert-mcp

# Default to running the MCP server (stdio transport)
ENTRYPOINT ["/usr/local/bin/dcert-mcp"]
