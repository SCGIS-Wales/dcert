# Lightweight Docker image that copies pre-built binaries from CI.
# No Rust compilation — the build-linux job already produces the binaries.
# Uses debian-slim (glibc) since binaries are built with x86_64-unknown-linux-gnu.

# Pinned by digest so rebuilding a given commit yields the same base layer.
# Dependabot's docker ecosystem opens a pull request when the tag moves on.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# dcert-mcp spawns the dcert binary as a subprocess and binds an unprivileged
# port, so it has no reason to run as uid 0. Create a system account for it.
RUN groupadd --system --gid 10001 dcert \
    && useradd --system --uid 10001 --gid dcert --create-home \
       --home-dir /home/dcert --shell /usr/sbin/nologin dcert

COPY docker-bin/dcert /usr/local/bin/dcert
COPY docker-bin/dcert-mcp /usr/local/bin/dcert-mcp
RUN chmod 0755 /usr/local/bin/dcert /usr/local/bin/dcert-mcp

USER dcert:dcert
WORKDIR /home/dcert

# Default to running the MCP server (stdio transport)
ENTRYPOINT ["/usr/local/bin/dcert-mcp"]
