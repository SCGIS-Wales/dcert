# dcert — TLS Certificate MCP Server

MCP server for TLS certificate analysis, format conversion, and key verification — for AI-powered IDEs.

## Features

Provides AI assistants (GitHub Copilot, JetBrains AI, Kiro, Claude, etc.) with tools for:

- **Decode certificates** — Parse PEM/DER files and display subject, issuer, validity, SANs, key usage
- **Check live TLS** — Connect to hosts and analyse certificate chains, protocols, cipher suites
- **Verify certificates** — Validate chains against system or custom trust stores
- **Convert formats** — PEM to DER, DER to PEM, PKCS#12 extraction
- **Inspect keys** — Verify key pairs match certificates, check key parameters

## Prerequisites

Install the `dcert` CLI (includes `dcert-mcp`):

```bash
brew tap SCGIS-Wales/tap
brew install dcert
```

Or download binaries from [GitHub Releases](https://github.com/SCGIS-Wales/dcert/releases).

## IDE Setup

### VS Code / Cursor

Install this extension — it automatically registers the MCP server with GitHub Copilot.

To override the binary path, set `dcert.mcp.path` in settings.

### JetBrains (IntelliJ, WebStorm, PyCharm, etc.)

JetBrains IDEs 2025.1+ have native MCP support. Go to **Settings > Tools > AI Assistant > Model Context Protocol (MCP)**, click **Add**, and paste:

```json
{
  "mcpServers": {
    "dcert-mcp": {
      "command": "dcert-mcp"
    }
  }
}
```

### Kiro

Add to `~/.kiro/settings/mcp.json` (global) or `.kiro/settings/mcp.json` (project):

```json
{
  "mcpServers": {
    "dcert-mcp": {
      "command": "dcert-mcp"
    }
  }
}
```

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "dcert-mcp": {
      "command": "dcert-mcp"
    }
  }
}
```

## License

MIT
