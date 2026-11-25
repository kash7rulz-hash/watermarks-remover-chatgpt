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
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse, Response  # noqa: E402
from starlette.routing import Route  # noqa: E402
import uvicorn  # noqa: E402


API_KEY = os.environ.get("WATERMARKS_SERVER_API_KEY", "").strip()
if len(API_KEY) < 32:
    raise RuntimeError(
        "Set WATERMARKS_SERVER_API_KEY to a random secret of at least 32 characters."
    )

MAX_INPUT_BYTES = engine.MAX_INPUT_BYTES
DOWNLOAD_TTL_SECONDS = 15 * 60
_DOWNLOADS: dict[str, tuple[bytes, str, str, float]] = {}

mcp = MCPServer("watermarks-remover")


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


class BearerAuthMiddleware:
    """Require a bearer token for MCP calls; health and one-time downloads are separate."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if scope.get("type") == "http" and path.rstrip("/") == "/mcp":
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            supplied = headers.get(b"authorization", b"").decode("latin-1")
            expected = f"Bearer {API_KEY}"
            if not hmac.compare_digest(supplied, expected):
                response = JSONResponse(
                    {"ok": False, "error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def main() -> None:
    port = int(os.environ.get("PORT", "10000"))
    external_url = os.environ.get("RENDER_EXTERNAL_URL") or os.environ.get("PUBLIC_BASE_URL")
    external_host = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(
        external_url or ""
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
        ]
    )
    protected_app = BearerAuthMiddleware(app)
    uvicorn.run(protected_app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
