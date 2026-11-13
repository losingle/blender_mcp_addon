"""Bounded protocol diagnostics with no credentials, query strings or tool data."""
from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import time

PATHS = {"/", "/mcp", "/sse", "/authorize", "/consent", "/token", "/revoke", "/register",
         "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
         "/.well-known/openid-configuration"}
RPC_METHODS = {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call",
               "resources/list", "resources/templates/list", "prompts/list"}
ERRORS = {"invalid_request", "invalid_client", "invalid_grant", "invalid_scope", "invalid_token",
          "unauthorized_client", "unsupported_grant_type", "upstream_unavailable"}
VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}


class DiagnosticsMiddleware:
    def __init__(self, app, path):
        self.app = app
        self.handler = RotatingFileHandler(Path(path), maxBytes=262144, backupCount=1, encoding="utf-8")
        self.handler.setFormatter(logging.Formatter("%(message)s"))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            try:
                return await self.app(scope, receive, send)
            finally:
                if scope["type"] == "lifespan":
                    self.handler.close()
        started = time.monotonic()
        headers = dict(scope.get("headers", []))
        raw_auth = headers.get(b"authorization", b"").split(b" ", 1)[0].lower()
        accepts = headers.get(b"accept", b"")
        path = scope.get("path", "")
        event = {"time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "path": path if path in PATHS else "other",
                 "method": scope["method"] if scope["method"] in {"GET", "HEAD", "POST", "DELETE", "OPTIONS"} else "other",
                 "auth": raw_auth.decode() if raw_auth in (b"bearer", b"basic") else ("other" if raw_auth else "none"),
                 "accept_json": b"application/json" in accepts,
                 "accept_sse": b"text/event-stream" in accepts,
                 "accept_any": b"*/*" in accepts}
        event["agent"] = "OpenAuth" if headers.get(b"user-agent", b"") == b"OpenAuth" else "other"
        if path in {"/token", "/revoke"}:
            length = headers.get(b"content-length", b"")
            event["content_length"] = int(length) if length.isdigit() and len(length) < 10 else None
            event["expect_continue"] = headers.get(b"expect", b"").lower() == b"100-continue"
            event["chunked"] = b"chunked" in headers.get(b"transfer-encoding", b"").lower()
            self.handler.handle(logging.LogRecord("oauth.protocol", logging.INFO, __file__, 0,
                json.dumps(dict(event, event="received")), (), None))
        request_body = bytearray()
        response_body = bytearray()
        status = 500

        async def read():
            message = await receive()
            if path == "/" and message["type"] == "http.request" and len(request_body) <= 16384:
                request_body.extend(message.get("body", b"")[:16385 - len(request_body)])
            return message

        async def write(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                reply_headers = dict(message.get("headers", []))
                content_type = reply_headers.get(b"content-type", b"")
                event["response_type"] = next((name for marker, name in (
                    (b"application/json", "json"), (b"text/event-stream", "sse"), (b"text/html", "html"))
                    if marker in content_type), "other")
                event["auth_challenge"] = b"www-authenticate" in reply_headers
            if message["type"] == "http.response.body" and status >= 400 and len(response_body) <= 2048:
                response_body.extend(message.get("body", b"")[:2049 - len(response_body)])
            await send(message)

        try:
            await self.app(scope, read, write)
        finally:
            event["event"] = "completed"
            event["status"] = status
            event["duration_ms"] = round((time.monotonic() - started) * 1000)
            if request_body and len(request_body) <= 16384:
                try:
                    data = json.loads(request_body)
                    if isinstance(data, dict):
                        event["rpc"] = data.get("method") if data.get("method") in RPC_METHODS else "other"
                        params = data.get("params")
                        if event["rpc"] == "initialize" and isinstance(params, dict):
                            version = params.get("protocolVersion")
                            event["protocol"] = version if version in VERSIONS else "other"
                except (ValueError, TypeError):
                    pass
            if response_body and len(response_body) <= 2048:
                try:
                    data = json.loads(response_body)
                    if isinstance(data, dict):
                        code = data.get("error")
                        if isinstance(code, str) and code in ERRORS:
                            event["error"] = code
                except (ValueError, TypeError):
                    pass
            self.handler.handle(logging.LogRecord("oauth.protocol", logging.INFO, __file__, 0,
                json.dumps(event), (), None))
