"""Stateful provider for the MCP SDK's OAuth authorization-code handlers."""
import hmac
import re
import secrets
import time
from urllib.parse import urlencode

from pydantic import AnyUrl
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    RefreshToken, TokenError, construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .config import Config
from .consent import AUTHORIZATION_SECONDS
from .store import Store


class Provider:
    def __init__(self, config: Config, store: Store):
        self.config, self.store = config, store

    async def get_client(self, client_id):
        c = self.config
        if not hmac.compare_digest(str(client_id).encode(), c.client_id.encode()):
            return None
        return OAuthClientInformationFull(
            client_id=c.client_id, client_secret=c.client_secret,
            client_name="Blender MCP (fixed client)",
            redirect_uris=[AnyUrl(u) for u in c.redirect_uris] or None,
            token_endpoint_auth_method="client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"], scope="blender",
        )

    async def register_client(self, client_info):
        raise NotImplementedError("Dynamic registration is disabled")

    async def authorize(self, client, params: AuthorizationParams):
        if not self.config.valid_resource(params.resource):
            raise AuthorizeError("invalid_request", "Incorrect resource")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "A valid S256 PKCE challenge is required")
        if not params.state or len(params.state) > 2048:
            raise AuthorizeError("invalid_request", "A nonempty state is required (max 2048 characters)")
        if (params.scopes or ["blender"]) != ["blender"]:
            raise AuthorizeError("invalid_scope", "Only the blender scope is supported")
        handle = secrets.token_urlsafe(32)
        self.store.put("pending", handle, params.model_dump(mode="json"), time.time() + AUTHORIZATION_SECONDS)
        return self.config.public_url + "/consent?" + urlencode({"request": handle})

    def finish(self, handle, allow):
        pending = self.store.get("pending", handle, consume=True)
        if not pending:
            return None
        p = AuthorizationParams.model_validate(pending["payload"])
        if not allow:
            return construct_redirect_uri(str(p.redirect_uri), error="access_denied", state=p.state)
        code = secrets.token_urlsafe(32)
        record = p.model_dump(mode="json")
        record.update(client_id=self.config.client_id, scopes=p.scopes or ["blender"],
                      resource=self.config.resource, subject="configured-owner")
        self.store.put("code", code, record, time.time() + 120)
        return construct_redirect_uri(str(p.redirect_uri), code=code, state=p.state)

    async def load_authorization_code(self, client, authorization_code):
        row = self.store.get("code", authorization_code)
        if row and row["payload"]["client_id"] == client.client_id:
            return AuthorizationCode(code=authorization_code, expires_at=row["expires"], **row["payload"])
        return None

    def issue(self, scopes, family=None, refresh=None, refresh_expires=None, *, code=None):
        family = family or secrets.token_urlsafe(24)
        previous_refresh = refresh
        access, refresh = secrets.token_urlsafe(32), refresh or secrets.token_urlsafe(48)
        now = int(time.time())
        common = dict(client_id=self.config.client_id, scopes=scopes,
                      resource=self.config.resource, subject="configured-owner")
        if not self.store.exchange(access, refresh, common, now + self.config.access_seconds,
                                   refresh_expires or now + self.config.refresh_seconds, family,
                                   code=code, previous_refresh=previous_refresh):
            raise TokenError("invalid_grant", "Grant expired, revoked or already used")
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=self.config.access_seconds,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        return self.issue(authorization_code.scopes, code=authorization_code.code)

    async def load_refresh_token(self, client, refresh_token):
        row = self.store.get("refresh", refresh_token)
        if row and row["payload"]["client_id"] == client.client_id:
            return RefreshToken(token=refresh_token, expires_at=int(row["expires"]), **row["payload"])
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        row = self.store.get("refresh", refresh_token.token)
        if not row or row["payload"]["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Refresh token expired or revoked")
        # Gemini Persistent Linking expects the same refresh token. The grant has a
        # fixed expiry (not extended), requires a confidential client, and is revocable.
        return self.issue(scopes, row["family"], refresh_token.token, row["expires"])

    async def load_access_token(self, token):
        row = self.store.get("access", token)
        if row:
            return AccessToken(token=token, expires_at=int(row["expires"]), **row["payload"])
        return None

    async def revoke_token(self, token):
        kind = "access" if isinstance(token, AccessToken) else "refresh"
        row = self.store.get(kind, token.token)
        if row:
            self.store.revoke(row["family"])
