# GitHub Codespaces deployment

This configuration runs two service surfaces:

- REST API: forwarded port 10000, protected by `WATERMARKS_SERVER_API_KEY`.
- MCP Streamable HTTP gateway: forwarded port 10001, endpoint `/mcp`, protected by OAuth 2.1 authorization code + PKCE.

The repository-scoped Codespaces secrets required are:

- `WATERMARKS_SERVER_API_KEY`: private bearer key for the original REST API.
- `WATERMARKS_OAUTH_PASSPHRASE`: private passphrase used on the OAuth approval page when connecting ChatGPT.

Do not put either secret in this repository or the plugin package. The OAuth server uses dynamic client registration, PKCE, short-lived access tokens, rotating refresh tokens, and a password-protected approval page. Tokens and DCR clients are kept in memory; stopping/restarting the Codespace means ChatGPT may need to reconnect and the owner must approve again.

The MCP server advertises per-tool OAuth scope metadata and protected-resource discovery. The Codespaces ports are public so ChatGPT can reach them, but tool calls require OAuth tokens. The OAuth approval page requires the private passphrase.

The MCP gateway returns short-lived (15-minute) download URLs for cleaned outputs. The gateway constructs these links from the Codespaces forwarded hostname.

The text-rewrite backend is not configured by default. Deterministic Unicode cleaning and supported file/container metadata operations are available subject to the live capability report. Pixel-level operations and statistical text rewriting must not be claimed unless their optional backends are installed and reported by the service.
