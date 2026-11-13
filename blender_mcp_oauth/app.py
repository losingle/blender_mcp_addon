"""OAuth endpoints and an authenticated, streaming HTTP reverse proxy."""
import base64
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import html
import hmac
import re
import time
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.datastructures import FormData
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError
from mcp.server.auth.routes import build_metadata, create_protected_resource_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import RequestBodyLimitMiddleware

from .config import Config
from .consent import ConsentForms, form_error, result_page
from .diagnostics import DiagnosticsMiddleware
from .provider import Provider
from .proxy import create_proxy
from .store import ConfigurationChanged, Store


def error(message, status=400):
    return JSONResponse({"error": "invalid_request", "error_description": message}, status_code=status)


class FixedClientAuthenticator:
    """Support both SDK-advertised confidential client authentication methods."""
    def __init__(self, provider):
        self.provider = provider

    async def authenticate_request(self, request):
        form = dict(await request.form())
        client_id, secret = form.get("client_id"), form.get("client_secret")
        auth = request.headers.get("authorization", "")
        if auth:
            if not auth.startswith("Basic ") or secret is not None:
                raise AuthenticationError("Use either Basic or form credentials")
            try:
                pair = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)
                basic_id, secret = map(unquote, pair)
            except (ValueError, UnicodeError):
                raise AuthenticationError("Invalid Basic credentials") from None
            if client_id is not None and basic_id != client_id:
                raise AuthenticationError("Client ID mismatch")
            client_id = basic_id
        client = await self.provider.get_client(str(client_id or ""))
        if (not client or not isinstance(secret, str)
                or not hmac.compare_digest(secret.encode(), self.provider.config.client_secret.encode())):
            raise AuthenticationError("Invalid client credentials")
        # The SDK's token/revocation models expect client_id in the form even for Basic auth.
        form.update(client_id=client_id, client_secret=secret)
        request._form = FormData(form)
        return client


class Limiter:
    def __init__(self):
        self.events = defaultdict(deque)

    def allow(self, bucket, limit):
        # Global buckets deliberately cannot be bypassed by spoofing forwarding/IP headers.
        now = time.monotonic()
        queue = self.events[bucket]
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= limit:
            return False
        queue.append(now)
        return True


def create_app(config: Config, store_path, upstream_transport=None, diagnostic_path=None):
    store = Store(store_path, config.fingerprint)
    provider = Provider(config, store)
    forms = ConsentForms(store)
    auth = FixedClientAuthenticator(provider)
    limiter = Limiter()
    sdk_authorize = AuthorizationHandler(provider)
    sdk_token = TokenHandler(provider, auth)
    sdk_revoke = RevocationHandler(provider, auth)
    issuer = AnyHttpUrl(config.public_url)
    metadata = build_metadata(issuer, None, ClientRegistrationOptions(
        enabled=False, valid_scopes=["blender"], default_scopes=["blender"]), RevocationOptions(enabled=True))

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            transport=upstream_transport, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(180, connect=5, pool=5),
        ) as client:
            app.state.http = client
            yield

    async def discovery(request):
        return JSONResponse(metadata.model_dump(mode="json", exclude_none=True))

    async def authorize(request):
        if not limiter.allow("authorize", 30):
            return error("Too many authorization requests. Retry in one minute.", 429)
        params = request.query_params if request.method == "GET" else await request.form()
        if len(params.multi_items()) != len(params):
            return error("Duplicate OAuth parameters are not accepted")
        if not config.redirect_uris:
            # Fail closed. No implicit callback enrollment or wildcard redirects.
            return error("No callback registered. Add Gemini's exact redirect_uri using add-redirect.")
        if params.get("code_challenge_method") != "S256":
            return error("PKCE S256 is required")
        return await sdk_authorize.handle(request)

    async def token_or_revoke(request):
        if not limiter.allow("token", 40):
            return error("Too many token requests. Retry in one minute.", 429)
        form = await request.form()
        if len(form.multi_items()) != len(form):
            return error("Duplicate OAuth parameters are not accepted")
        if not config.valid_resource(form.get("resource")):
            return error("Incorrect resource")
        if request.url.path == "/token" and form.get("grant_type") == "authorization_code":
            if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", str(form.get("code_verifier", ""))):
                return error("Invalid PKCE verifier")
        return await (sdk_token if request.url.path == "/token" else sdk_revoke).handle(request)

    def consent_html(handle, nonce, pending, failed=False):
        callback = html.escape(pending["payload"]["redirect_uri"])
        name = html.escape(config.client_id)
        note = "Client Secret 不正确，请重试。" if failed else "请输入你配置的 Client Secret，确认将 Blender 控制权授予此客户端。"
        return f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>授权 Blender MCP</title>
<style>body{{font:16px/1.6 system-ui,sans-serif;background:#f5f5f2;color:#202826;margin:0;padding:8vh 20px}}
main{{max-width:520px;margin:auto;padding:32px;background:white;border:1px solid #d8dedb;border-radius:16px}}
h1{{font-size:27px;margin:0 0 16px}}p{{overflow-wrap:anywhere}}small{{color:#58635d}}
input{{box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid #829188;border-radius:7px}}
button{{margin:20px 12px 0 0;padding:11px 22px;font:inherit;cursor:pointer;border:1px solid #87958d;border-radius:7px}}
button[value=allow]{{color:white;background:#255741;border-color:#255741}}</style>
<main><h1>授权 Blender MCP</h1><p>客户端：<strong>{name}</strong></p>
<p>此权限允许读取和修改场景、执行 Python，并可能读写 Blender 进程可访问的本机文件。</p>
<p><small>回调地址：{callback}</small></p><p role="status">{note}</p>
<form method="post" action="/consent">
<input type="hidden" name="request" value="{html.escape(handle)}">
<input type="hidden" name="csrf" value="{nonce}">
<label for="secret">Client Secret</label>
<input id="secret" type="password" name="client_secret" autocomplete="off" maxlength="512">
<button name="decision" value="allow">确认授权</button><button name="decision" value="deny">拒绝</button>
</form></main></html>'''

    async def consent(request: Request):
        if request.method in ("GET", "HEAD"):
            if not limiter.allow("consent_get", 40):
                return error("Too many requests", 429)
            handle = request.query_params.get("request", "")
            pending = store.get("pending", handle)
            if not pending:
                return form_error("request_expired", handle, False)
            cookie_name = forms.cookie_name(handle)
            nonce, max_age = forms.issue(handle, request.cookies.get(cookie_name, ""), pending["expires"])
            response = HTMLResponse(consent_html(handle, nonce, pending))
            response.set_cookie(cookie_name, nonce, secure=True, httponly=True,
                                samesite="lax", path="/", max_age=max_age)
            return response
        if not limiter.allow("consent_post", 10):
            return error("Too many attempts. Retry in one minute.", 429)
        if request.headers.get("origin", config.public_url) != config.public_url:
            return error("Invalid form origin", 403)
        form = await request.form()
        if len(form.multi_items()) != len(form):
            return error("Duplicate form fields", 400)
        handle, csrf = str(form.get("request", "")), str(form.get("csrf", ""))
        pending = store.get("pending", handle)
        if not pending:
            return form_error("request_expired", handle, False)
        cookie_name = forms.cookie_name(handle)
        reason = forms.check(handle, csrf, request.cookies.get(cookie_name, ""))
        if reason:
            return form_error(reason, handle, True)
        decision = form.get("decision")
        if decision not in ("allow", "deny"):
            return error("Choose allow or deny")
        if decision == "allow":
            secret = str(form.get("client_secret", ""))
            if not hmac.compare_digest(secret.encode(), config.client_secret.encode()):
                return HTMLResponse(consent_html(handle, csrf, pending, failed=True), status_code=401)
        redirect = provider.finish(handle, decision == "allow")
        if not redirect:
            return form_error("request_expired", handle, False)
        forms.consume(csrf)
        # A real result document avoids a cross-site redirect attached to the
        # secret-bearing form POST and supplies a visible recovery action.
        response = result_page("授权已确认" if decision == "allow" else "已拒绝授权",
            "正在返回 Gemini。如果没有自动跳转，请点击下方按钮继续。",
            redirect, label="返回 Gemini", auto=True)
        response.delete_cookie(cookie_name, path="/", secure=True, httponly=True, samesite="lax")
        return response

    routes = [
        Route("/.well-known/oauth-authorization-server", discovery),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/token", token_or_revoke, methods=["POST"]),
        Route("/revoke", token_or_revoke, methods=["POST"]),
        Route("/consent", consent, methods=["GET", "POST"]),
        *create_protected_resource_routes(AnyHttpUrl(config.resource), [issuer], ["blender"], "Blender MCP"),
        Route("/", create_proxy(config, provider), methods=["GET", "HEAD", "POST", "DELETE"]),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.provider, app.state.store = provider, store

    async def boundary(request, call_next):
        if request.url.path != "/":
            if len(request.scope.get("query_string", b"")) > 8192:
                return error("Request too large", 413)
            if len(await request.body()) > 16384:
                return error("Request too large", 413)
        try:
            response = await call_next(request)
        except ConfigurationChanged:
            response = error("OAuth configuration changed. Restart the gateway.", 503)
        consent_page = request.url.path == "/consent"
        # no-referrer makes Chromium send Origin: null on a non-CORS form POST.
        # Preserve the same-origin form Origin without leaking referrers to Google.
        referrer_policy = "same-origin" if consent_page else "no-referrer"
        # Chromium applies form-action to the POST's redirect as well. Permit the
        # registered callback paths; the provider still validates exact URIs.
        callbacks = " ".join(str(AnyHttpUrl(uri)).split("?", 1)[0] for uri in config.redirect_uris)
        form_actions = "'self'" + (" " + callbacks if consent_page and callbacks else "")
        response.headers.update({
            "Cache-Control": "no-store", "Pragma": "no-cache",
            "Referrer-Policy": referrer_policy, "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action "
                + form_actions + "; frame-ancestors 'none'; base-uri 'none'",
        })
        return response

    app.add_middleware(BaseHTTPMiddleware, dispatch=boundary)
    app.add_middleware(RequestBodyLimitMiddleware, max_body_size=8 * 1024 * 1024)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[urlsplit(config.public_url).hostname,
                                                           "127.0.0.1", "localhost", "host.docker.internal"])
    if diagnostic_path is not None:
        app.add_middleware(DiagnosticsMiddleware, path=diagnostic_path)
    return app
