#!/usr/bin/env python3
"""Authenticated MCP gateway for the Watermarks Remover engine."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import mimetypes
import os
import secrets
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from urllib.parse import quote
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server as engine  # noqa: E402

from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp.server.auth.provider import (  # noqa: E402
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError, OAuthAuthorizationServerProvider,
    RefreshToken, RegistrationError, TokenError, construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions  # noqa: E402
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken  # noqa: E402
from pydantic import AnyHttpUrl  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response  # noqa: E402
from starlette.routing import Route  # noqa: E402
import uvicorn  # noqa: E402

PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "").rstrip("/")
OAUTH_PASSWORD = os.environ.get("WATERMARKS_OAUTH_PASSPHRASE", "").strip()
if not PUBLIC_BASE_URL.startswith("https://"):
    raise RuntimeError("Set PUBLIC_BASE_URL to the public HTTPS base URL for this service.")
if len(OAUTH_PASSWORD) < 32:
    raise RuntimeError("Set WATERMARKS_OAUTH_PASSPHRASE to a random secret of at least 32 characters.")

OAUTH_SCOPE = "watermarks:use"
RESOURCE_URL = f"{PUBLIC_BASE_URL}/mcp"
OAUTH_TOKEN_TTL_SECONDS = 8 * 60 * 60
OAUTH_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60


MAX_INPUT_BYTES = engine.MAX_INPUT_BYTES
DOWNLOAD_TTL_SECONDS = 15 * 60
_DOWNLOADS: dict[str, tuple[bytes, str, str, float]] = {}



class WatermarksOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Single-user OAuth 2.1 provider with PKCE and a password-protected approval page.

    Tokens and DCR clients are held in memory. A Codespace restart invalidates
    sessions, requiring ChatGPT to reconnect and the owner to approve again.
    """

    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams, float]] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.failed_logins: dict[str, list[float]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise RegistrationError(error="invalid_client_metadata", error_description="client_id is required")
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        scopes = params.scopes or [OAUTH_SCOPE]
        if any(scope != OAUTH_SCOPE for scope in scopes):
            raise AuthorizeError(error="invalid_scope", error_description="The requested OAuth scope is not supported")
        if params.resource and params.resource.rstrip("/") != RESOURCE_URL.rstrip("/"):
            raise AuthorizeError(error="invalid_target", error_description="The requested resource does not match this endpoint")
        if not client.client_id:
            raise AuthorizeError(error="unauthorized_client", error_description="The OAuth client is not registered")
        pending_state = secrets.token_urlsafe(32)
        self.pending[pending_state] = (client, params, time.time() + 10 * 60)
        return f"{PUBLIC_BASE_URL}/oauth/approve?state={pending_state}"

    def _allow_login(self, ip: str) -> bool:
        now = time.time()
        recent = [stamp for stamp in self.failed_logins.get(ip, []) if now - stamp < 15 * 60]
        self.failed_logins[ip] = recent
        return len(recent) < 8

    async def approve(self, state: str, supplied_password: str, ip: str) -> str | None:
        pending = self.pending.get(state)
        if pending is None:
            return None
        client, params, expires_at = pending
        if expires_at <= time.time():
            self.pending.pop(state, None)
            return None
        if not self._allow_login(ip):
            return None
        if not hmac.compare_digest(supplied_password.encode("utf-8"), OAUTH_PASSWORD.encode("utf-8")):
            self.failed_logins.setdefault(ip, []).append(time.time())
            return None
        self.pending.pop(state, None)
        self.failed_logins.pop(ip, None)
        scopes = params.scopes or [OAUTH_SCOPE]
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=time.time() + 5 * 60,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource or RESOURCE_URL,
            subject="owner",
        )
        self.codes[code.code] = code
        return construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state)

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        code = self.codes.get(authorization_code)
        if code is None or code.expires_at <= time.time() or code.client_id != client.client_id:
            self.codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        if authorization_code.expires_at <= time.time() or authorization_code.client_id != client.client_id:
            raise TokenError(error="invalid_grant", error_description="The authorization code is expired or invalid")
        self.codes.pop(authorization_code.code, None)
        access_value = secrets.token_urlsafe(48)
        refresh_value = secrets.token_urlsafe(48)
        now = int(time.time())
        resource = authorization_code.resource or RESOURCE_URL
        self.access_tokens[access_value] = AccessToken(
            token=access_value,
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + OAUTH_TOKEN_TTL_SECONDS,
            resource=resource,
            subject=authorization_code.subject or "owner",
        )
        self.refresh_tokens[refresh_value] = RefreshToken(
            token=refresh_value,
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + OAUTH_REFRESH_TTL_SECONDS,
            subject=authorization_code.subject or "owner",
        )
        return OAuthToken(
            access_token=access_value,
            token_type="Bearer",
            expires_in=OAUTH_TOKEN_TTL_SECONDS,
            refresh_token=refresh_value,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = self.access_tokens.get(token)
        if access is None:
            return None
        if access.expires_at is not None and access.expires_at <= int(time.time()):
            self.access_tokens.pop(token, None)
            return None
        return access

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        token = self.refresh_tokens.get(refresh_token)
        if token is None or token.client_id != client.client_id:
            return None
        if token.expires_at is not None and token.expires_at <= int(time.time()):
            self.refresh_tokens.pop(refresh_token, None)
            return None
        return token

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        if refresh_token.client_id != client.client_id:
            raise TokenError(error="invalid_grant", error_description="The refresh token does not belong to this client")
        if any(scope not in refresh_token.scopes for scope in scopes):
            raise TokenError(error="invalid_scope", error_description="The requested refresh scope was not previously granted")
        self.refresh_tokens.pop(refresh_token.token, None)
        access_value = secrets.token_urlsafe(48)
        refresh_value = secrets.token_urlsafe(48)
        now = int(time.time())
        granted_scopes = scopes or refresh_token.scopes
        self.access_tokens[access_value] = AccessToken(
            token=access_value,
            client_id=client.client_id,
            scopes=granted_scopes,
            expires_at=now + OAUTH_TOKEN_TTL_SECONDS,
            resource=RESOURCE_URL,
            subject=refresh_token.subject or "owner",
        )
        self.refresh_tokens[refresh_value] = RefreshToken(
            token=refresh_value,
            client_id=client.client_id,
            scopes=granted_scopes,
            expires_at=now + OAUTH_REFRESH_TTL_SECONDS,
            subject=refresh_token.subject or "owner",
        )
        return OAuthToken(
            access_token=access_value,
            token_type="Bearer",
            expires_in=OAUTH_TOKEN_TTL_SECONDS,
            refresh_token=refresh_value,
            scope=" ".join(granted_scopes),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.access_tokens.pop(token.token, None)
        self.refresh_tokens.pop(token.token, None)


oauth_provider = WatermarksOAuthProvider()
oauth_settings = AuthSettings(
    issuer_url=AnyHttpUrl(PUBLIC_BASE_URL),
    resource_server_url=AnyHttpUrl(RESOURCE_URL),
    required_scopes=[OAUTH_SCOPE],
    client_registration_options=ClientRegistrationOptions(
        enabled=True,
        valid_scopes=[OAUTH_SCOPE],
        default_scopes=[OAUTH_SCOPE],
    ),
    validate_token_resource=True,
)
mcp = MCPServer(
    "watermarks-remover",
    auth=oauth_settings,
    auth_server_provider=oauth_provider,
)


def _decode_input(filename: str, file_base64: str) -> tuple[bytes, str]:
    if not isinstance(file_base64, str):
        raise ValueError("file_base64 must be a base64-encoded string")
    if len(file_base64) > ((MAX_INPUT_BYTES * 4 // 3) + 16):
        raise ValueError(f"File exceeds the {MAX_INPUT_BYTES}-byte input limit")
    try:
        data = base64.b64decode(file_base64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("file_base64 is not valid base64") from None
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"File exceeds the {MAX_INPUT_BYTES}-byte input limit")
    safe_name = engine._safe_name(filename or "input")
    return data, safe_name


def _stats_value(stats: Any) -> Any:
    if hasattr(stats, "to_dict"):
        return stats.to_dict()
    if is_dataclass(stats):
        return asdict(stats)
    if isinstance(stats, (dict, list, str, int, float, bool)) or stats is None:
        return stats
    if hasattr(stats, "__dict__"):
        return vars(stats)
    return str(stats)


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _create_download(filename: str, data: bytes) -> str:
    now = time.time()
    expired = [key for key, item in _DOWNLOADS.items() if item[3] <= now]
    for key in expired:
        _DOWNLOADS.pop(key, None)

    token = secrets.token_urlsafe(32)
    media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    _DOWNLOADS[token] = (data, filename, media_type, now + DOWNLOAD_TTL_SECONDS)

    base_url = (
        os.environ.get("PUBLIC_BASE_URL")
        or os.environ.get("RENDER_EXTERNAL_URL")
        or ""
    ).rstrip("/")
    if not base_url:
        raise RuntimeError("Render's public service URL is not available yet")
    return f"{base_url}/download/{token}"


@mcp.tool()
def get_capabilities() -> dict[str, Any]:
    """Report the cleaning tools and optional backends actually available in this deployment."""
    return _json_safe(
        {
            "engine": engine.capabilities(),
            "input_limit_bytes": MAX_INPUT_BYTES,
            "text_rewrite_backend_configured": bool(
                os.environ.get("WATERMARKS_REWRITE_MODEL")
                and os.environ.get("WATERMARKS_REWRITE_BASE_URL")
            ),
            "notes": [
                "Optional pixel-removal and SynthID features are available only when their backends are installed.",
                "Statistical text rewriting is not enabled by this gateway unless a rewrite backend is configured.",
            ],
        }
    )


@mcp.tool()
def inspect_file(
    filename: str,
    file_base64: str,
    run_text_detectors: bool = False,
) -> dict[str, Any]:
    """Inspect an attached file for supported Unicode, metadata, provenance and detector signals.

    Pass the original file bytes as base64 and include its filename with the extension.
    """
    data, safe_name = _decode_input(filename, file_base64)
    result = engine._inspect_payload(data, safe_name, bool(run_text_detectors))
    return _json_safe(result)


@mcp.tool()
def clean_file(
    filename: str,
    file_base64: str,
    keep_non_ai_metadata: bool = True,
    strip_all_metadata: bool = False,
    nfkc: bool = False,
    aggressive_homoglyphs: bool = False,
    normalize_spaces: bool = True,
    also_layer_a_text: bool = True,
) -> dict[str, Any]:
    """Clean supported invisible Unicode marks and file metadata, then return a short-lived download URL.

    The default preserves unrelated non-AI metadata where supported. Set strip_all_metadata
    only when you intentionally want all supported metadata removed. Statistical text rewriting
    is not performed unless a rewrite backend is configured separately.
    """
    data, safe_name = _decode_input(filename, file_base64)
    kind = engine.classify_bytes(data, Path(safe_name).suffix)

    if kind == "unknown":
        raise ValueError(
            "Unrecognized format. Use a supported file type and retain its filename extension."
        )

    if kind == "text":
        if engine.looks_binary(data):
            raise ValueError("Refusing to treat binary content as plain text")
        original_text = data.decode("utf-8", errors="surrogateescape")
        cleaned_text, stats = engine.clean_text(
            original_text,
            nfkc=bool(nfkc),
            aggressive_homoglyphs=bool(aggressive_homoglyphs),
            normalize_spaces=bool(normalize_spaces),
        )
        cleaned_bytes = cleaned_text.encode("utf-8", errors="surrogateescape")
        report = {
            "kind": "text",
            "layer_a_unicode_cleaning": "completed",
            "stats": _stats_value(stats),
            "layer_b_statistical_rewrite": (
                "not run; no rewrite backend is configured for this deployment"
            ),
            "remaining_unicode_findings": engine.inspect_text(cleaned_text).to_dict(),
        }
    else:
        options = {
            "keep_non_ai_metadata": bool(keep_non_ai_metadata),
            "strip_all_metadata": bool(strip_all_metadata),
            "also_layer_a_text": bool(also_layer_a_text),
        }
        result = engine._clean_payload(data, safe_name, options)
        cleaned_bytes = base64.b64decode(result["cleaned"], validate=True)
        report = result["report"]

    path = Path(safe_name)
    output_name = f"{path.stem}.cleaned{path.suffix}" if path.suffix else f"{path.name}.cleaned"
    download_url = _create_download(output_name, cleaned_bytes)
    return {
        "ok": True,
        "filename": output_name,
        "download_url": download_url,
        "download_expires_in_seconds": DOWNLOAD_TTL_SECONDS,
        "report": _json_safe(report),
    }




class ChatGPTSecuritySchemesMiddleware:
    """Inject the ChatGPT tool-level OAuth scheme into tools/list JSON responses.

    The MCP wire type package currently ignores unknown root fields. ChatGPT's
    custom MCP client consumes `securitySchemes` at the tool root, while other
    MCP clients safely ignore this additive extension.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        start_message: dict[str, Any] | None = None
        chunks: list[bytes] = []
        content_type = b""

        async def capture(message: dict[str, Any]) -> None:
            nonlocal start_message, content_type
            if message["type"] == "http.response.start":
                start_message = message
                headers = {k.lower(): v for k, v in message.get("headers", [])}
                content_type = headers.get(b"content-type", b"").lower()
                return
            if message["type"] == "http.response.body" and start_message is not None:
                chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return
                body = b"".join(chunks)
                if b"application/json" in content_type:
                    try:
                        payload = json.loads(body)
                        tool_list = payload.get("result", {}).get("tools")
                        if isinstance(tool_list, list):
                            scheme = [{"type": "oauth2", "scopes": [OAUTH_SCOPE]}]
                            for tool in tool_list:
                                if isinstance(tool, dict):
                                    tool["securitySchemes"] = scheme
                                    meta = tool.setdefault("_meta", {})
                                    if isinstance(meta, dict):
                                        meta["securitySchemes"] = scheme
                            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                            header_list = [(k, v) for k, v in start_message.get("headers", []) if k.lower() != b"content-length"]
                            header_list.append((b"content-length", str(len(body)).encode("ascii")))
                            start_message = {**start_message, "headers": header_list}
                    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError):
                        pass
                await send(start_message)
                await send({"type": "http.response.body", "body": body, "more_body": False})
                start_message = None
                chunks.clear()
                return
            if start_message is not None:
                await send(start_message)
                start_message = None
            await send(message)

        await self.app(scope, receive, capture)


async def health(_request: Request) -> Response:
    return JSONResponse({"ok": True, "service": "watermarks-remover-mcp"})


async def download(request: Request) -> Response:
    token = request.path_params["token"]
    item = _DOWNLOADS.get(token)
    if item is None:
        return JSONResponse({"ok": False, "error": "download expired or not found"}, status_code=404)
    data, filename, media_type, expires_at = item
    if expires_at <= time.time():
        _DOWNLOADS.pop(token, None)
        return JSONResponse({"ok": False, "error": "download expired"}, status_code=410)
    quoted_name = quote(filename, safe="")
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_name}",
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def oauth_approve(request: Request) -> Response:
    state = request.query_params.get("state", "")
    if request.method == "GET":
        if not state or state not in oauth_provider.pending:
            return HTMLResponse("<h2>Authorization link expired</h2><p>Restart the connection from ChatGPT.</p>", status_code=400)
        html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Watermarks Remover</title>
<style>body{{font:16px system-ui,sans-serif;background:#f5f6f8;margin:0;padding:32px;color:#18202b}}main{{max-width:460px;margin:7vh auto;background:white;padding:30px;border-radius:14px;box-shadow:0 8px 32px #0001}}input{{box-sizing:border-box;width:100%;padding:12px;margin:10px 0 18px;border:1px solid #bbb;border-radius:8px}}button{{padding:12px 18px;background:#18202b;color:white;border:0;border-radius:8px;cursor:pointer}}small{{color:#555;line-height:1.5}}</style></head>
<body><main><h2>Connect Watermarks Remover</h2>
<p>ChatGPT is requesting permission to inspect and clean files you provide to it.</p>
<p><strong>Only approve this request if you initiated the connection in ChatGPT.</strong></p>
<form method="post" action="/oauth/approve"><input type="hidden" name="state" value="{state}">
<label for="password">Private connection passphrase</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Approve ChatGPT connection</button></form>
<small>This authorizes the Watermarks Remover tools for your ChatGPT account. It does not grant access to your GitHub account or other files. You can revoke the connection from ChatGPT.</small>
</main></body></html>"""
        return HTMLResponse(html, headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})

    body = (await request.body()).decode("utf-8", errors="replace")
    fields = parse_qs(body, keep_blank_values=True)
    state = fields.get("state", [""])[0]
    password = fields.get("password", [""])[0]
    ip = request.client.host if request.client else "unknown"
    redirect_uri = await oauth_provider.approve(state, password, ip)
    if redirect_uri is None:
        return HTMLResponse(
            "<h2>Approval failed</h2><p>The passphrase was incorrect, the link expired, or too many attempts were made. Restart the connection and try again.</p>",
            status_code=401,
            headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"},
        )
    return RedirectResponse(redirect_uri, status_code=303, headers={"Cache-Control": "no-store"})


def main() -> None:
    port = int(os.environ.get("PORT", "10000"))
    external_host = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(
        PUBLIC_BASE_URL
    ).netloc
    allowed_hosts = [external_host] if external_host else ["localhost:*", "127.0.0.1:*"]
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        json_response=True,
        host="0.0.0.0",
        max_request_body_size=max(16 * 1024 * 1024, MAX_INPUT_BYTES * 2),
        transport_security=TransportSecuritySettings(allowed_hosts=allowed_hosts),
    )
    app.routes.extend(
        [
            Route("/health", health, methods=["GET"]),
            Route("/download/{token}", download, methods=["GET"]),
            Route("/oauth/approve", oauth_approve, methods=["GET", "POST"]),
        ]
    )
    wrapped_app = ChatGPTSecuritySchemesMiddleware(app)
    uvicorn.run(wrapped_app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
