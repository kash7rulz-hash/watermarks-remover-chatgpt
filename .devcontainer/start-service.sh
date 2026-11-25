#!/usr/bin/env bash
set -euo pipefail

for name in WATERMARKS_SERVER_API_KEY WATERMARKS_OAUTH_PASSPHRASE; do
  if [[ -z "${!name:-}" ]]; then
    echo "Missing Codespaces secret: ${name}. Add it in GitHub Settings > Codespaces > Secrets, grant this repository access, then restart the Codespace." >&2
    exit 1
  fi
done

: "${CODESPACE_NAME:?GitHub Codespaces did not provide CODESPACE_NAME}"
: "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:?GitHub Codespaces did not provide the port-forwarding domain}"
PUBLIC_MCP_URL="https://${CODESPACE_NAME}-10001.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
REST_LOG=/tmp/watermarks-remover-rest.log
MCP_LOG=/tmp/watermarks-remover-mcp.log

if ! curl --fail --silent -H "Authorization: Bearer ${WATERMARKS_SERVER_API_KEY}" \
    http://127.0.0.1:10000/health >/dev/null 2>&1; then
  nohup python3 service/scripts/server.py --host 0.0.0.0 --port 10000 \
    >"$REST_LOG" 2>&1 </dev/null &
fi

if ! curl --fail --silent http://127.0.0.1:10001/health >/dev/null 2>&1; then
  nohup env PORT=10001 PUBLIC_BASE_URL="$PUBLIC_MCP_URL" \
    python3 service/scripts/mcp_gateway.py >"$MCP_LOG" 2>&1 </dev/null &
fi

rest_ok=false
mcp_ok=false
for _ in $(seq 1 60); do
  if curl --fail --silent -H "Authorization: Bearer ${WATERMARKS_SERVER_API_KEY}" \
      http://127.0.0.1:10000/health >/dev/null 2>&1; then
    rest_ok=true
  fi
  if curl --fail --silent http://127.0.0.1:10001/health >/dev/null 2>&1; then
    mcp_ok=true
  fi
  if [[ "$rest_ok" == true && "$mcp_ok" == true ]]; then
    echo "Watermarks Remover REST API is healthy on port 10000."
    echo "Watermarks Remover OAuth-protected MCP gateway is healthy on port 10001."
    echo "MCP endpoint: ${PUBLIC_MCP_URL}/mcp"
    exit 0
  fi
  sleep 1
done

echo "Watermarks Remover services did not both become healthy." >&2
echo "--- REST log ---" >&2
tail -n 80 "$REST_LOG" >&2 2>/dev/null || true
echo "--- MCP log ---" >&2
tail -n 160 "$MCP_LOG" >&2 2>/dev/null || true
exit 1
