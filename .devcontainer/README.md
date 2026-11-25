# GitHub Codespaces deployment

This Codespaces configuration runs both supported service surfaces:

- REST API: forwarded port 10000
- MCP Streamable HTTP gateway: forwarded port 10001, endpoint `/mcp`

Both services require the repository-scoped Codespaces secret
`WATERMARKS_SERVER_API_KEY`. The MCP endpoint uses bearer authentication.
Do not put the key in this repository or in plugin files.

The MCP gateway returns short-lived (15-minute) download URLs for cleaned
outputs. The gateway constructs those links from the Codespaces forwarded
hostname. The Codespaces ports are public so ChatGPT can reach them; the
MCP API remains protected by the bearer key.

The native REST API matches the service contract used by the separate
`remove-ai-marks` skill. The MCP gateway exposes equivalent chat tools
`get_capabilities`, `inspect_file`, and `clean_file`.

The text-rewrite backend is not configured by default. Deterministic Unicode
cleaning and supported file/container metadata operations are available
subject to the live capability report. Pixel-level operations and statistical
text rewriting must not be claimed unless their optional backends are installed
and reported by the service.
