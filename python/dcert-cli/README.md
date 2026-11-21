# dcert

TLS certificate analysis, format conversion and key verification from the
command line. This package installs the `dcert` executable and nothing else: no
Python code runs when you type `dcert`, and the package has no Python
dependencies.

```bash
pip install dcert
dcert --version
dcert example.com
```

Wheels exist for Linux x86_64 (glibc 2.34 or later), macOS Intel, macOS Apple
Silicon and Windows x86_64. On any other platform pip reports "no matching
distribution"; build from source instead:

```bash
cargo install --git https://github.com/SCGIS-Wales/dcert --locked --bin dcert dcert
```

## MCP server

The Model Context Protocol server is a separate package,
[`dcert-mcp`](https://pypi.org/project/dcert-mcp/):

```bash
pip install dcert-mcp
```

## Documentation

Full documentation, the changelog and the security policy are in the
[repository](https://github.com/SCGIS-Wales/dcert).
