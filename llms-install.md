# IDA Pro MCP Fusion install notes

IDA Pro MCP Fusion is a local stdio MCP server for IDA Pro reverse engineering. It requires IDA Pro 8.3 or newer, Python 3.11+, and `uv`/`uvx`. IDA Free is not supported.

Use this MCP configuration:

```json
{
  "mcpServers": {
    "ida-pro-mcp-fusion": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/rison1337/ida-pro-mcp-fusion",
        "idalib-mcp",
        "--stdio"
      ]
    }
  }
}
```

The stdio entry point is:

```bash
uvx --from git+https://github.com/rison1337/ida-pro-mcp-fusion idalib-mcp --stdio
```

If IDA's Python runtime is not configured, run Hex-Rays `idapyswitch` first and select the Python 3.11+ environment that has the `idapro` package available.

After installation, open a binary through the MCP server with `idb_open` or use `idb_batch_open` for multiple binaries. The server exposes 76 tools, including persistent SQLite cache tools and multi-binary headless session management.
