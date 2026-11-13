import base64
from dataclasses import replace
import hashlib
import html
import json
from pathlib import Path
import re
import secrets
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.testclient import TestClient

from blender_mcp_oauth.app import create_app
from blender_mcp_oauth.config import Config
from blender_mcp_oauth.store import Store


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "tokens.sqlite3"
        self.callback = "https://oauth-redirect.googleusercontent.com/r/test-blender"
        self.config = Config("https://blender.example.com", "gemini-test", secrets.token_urlsafe(48),
                             (self.callback,))
        self.forwarded = []

        async def upstream(request):
            self.forwarded.append(request)
            data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode()
            return httpx.Response(200, headers={"content-type": "application/json", "mcp-session-id": "sample"},
                                  stream=httpx.ByteStream(data))

        self.transport = httpx.MockTransport(upstream)
        self.app = create_app(self.config, self.path, self.transport)
        self.client = TestClient(self.app, base_url=self.config.public_url, follow_redirects=False)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def begin(self, **changes):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        params = dict(client_id=self.config.client_id, redirect_uri=self.callback, response_type="code",
                      code_challenge=challenge, code_challenge_method="S256", state="random-client-state",
                      resource=self.config.resource, scope="blender")
        params.update(changes)
        result = self.client.get("/authorize", params=params)
        return result, verifier

    def form(self):
        result, verifier = self.begin()
        self.assertEqual(result.status_code, 302, result.text)
        page = self.client.get(result.headers["location"])
        self.assertEqual(page.status_code, 200, page.text)
        form = {name: re.search(f'name="{name}" value="([^"]+)"', page.text).group(1)
                for name in ("request", "csrf")}
        form.update(decision="allow", client_secret=self.config.client_secret)
        return form, verifier

    def code(self):
        form, verifier = self.form()
        response = self.client.post("/consent", data=form, headers={"Origin": self.config.public_url})
        query = parse_qs(urlsplit(self.callback_url(response)).query)
        self.assertEqual(query["state"], ["random-client-state"])
        return query["code"][0], verifier

    def callback_url(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('http-equiv="refresh"', response.text)
        self.assertNotIn(self.config.client_secret, response.text)
        return html.unescape(re.search(r'id="continue" href="([^"]+)"', response.text).group(1))

    def exchange(self, code, verifier, **changes):
        form = dict(grant_type="authorization_code", client_id=self.config.client_id,
                    client_secret=self.config.client_secret, code=code, redirect_uri=self.callback,
                    code_verifier=verifier, resource=self.config.resource)
        form.update(changes)
        return self.client.post("/token", data=form)

    def tokens(self):
        code, verifier = self.code()
        response = self.exchange(code, verifier)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def refresh(self, token, **changes):
        form = dict(grant_type="refresh_token", client_id=self.config.client_id,
                    client_secret=self.config.client_secret, refresh_token=token, resource=self.config.resource)
        form.update(changes)
        return self.client.post("/token", data=form)

    def test_anonymous_methods_blocked_without_forwarding(self):
        for method in ("GET", "HEAD", "POST", "DELETE"):
            response = self.client.request(method, "/")
            self.assertEqual(response.status_code, 401)
            self.assertIn("oauth-protected-resource", response.headers["www-authenticate"])
        self.assertEqual(self.forwarded, [])

    def test_metadata_manual_client_only(self):
        data = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(data["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(data["grant_types_supported"], ["authorization_code", "refresh_token"])
        self.assertNotIn("registration_endpoint", data)
        self.assertEqual(self.client.post("/register").status_code, 404)
        resource = self.client.get("/.well-known/oauth-protected-resource").json()
        self.assertEqual(resource["resource"], self.config.resource)
        self.assertEqual(resource["scopes_supported"], ["blender"])

    def test_unregistered_redirect_never_redirects(self):
        response, _ = self.begin(redirect_uri="https://evil.example/steal")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("location", response.headers)

    def test_no_callback_is_fail_closed(self):
        app = create_app(replace(self.config, redirect_uris=()), Path(self.tmp.name) / "empty.db")
        with TestClient(app, base_url=self.config.public_url) as client:
            response = client.get("/authorize", params={"client_id": self.config.client_id})
            self.assertEqual(response.status_code, 400)
            self.assertIn("No callback registered", response.text)

    def test_unknown_client(self):
        response, _ = self.begin(client_id="unknown")
        self.assertEqual(response.status_code, 400)

    def test_pkce_s256_required(self):
        response, _ = self.begin(code_challenge_method="plain")
        self.assertEqual(response.status_code, 400)

    def test_wrong_resource_and_scope(self):
        response, _ = self.begin(resource="https://evil.example/")
        self.assertIn("error=invalid_request", response.headers["location"])
        response, _ = self.begin(scope="admin")
        self.assertIn("error=invalid_scope", response.headers["location"])

    def test_consent_requires_secret_and_csrf(self):
        form, _ = self.form()
        bad = dict(form, client_secret="incorrect")
        response = self.client.post("/consent", data=bad)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(self.config.client_secret, response.text)
        self.assertNotIn("incorrect", response.text)
        response = self.client.post("/consent", data=dict(form, csrf="wrong"))
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/consent", data=form, headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_deny_never_issues_code(self):
        form, _ = self.form()
        response = self.client.post("/consent", data=dict(form, decision="deny", client_secret=""))
        callback = self.callback_url(response)
        self.assertIn("error=access_denied", callback)
        self.assertNotIn("code=", callback)

    def test_null_origin_is_still_rejected(self):
        form, _ = self.form()
        response = self.client.post("/consent", data=form, headers={"Origin": "null"})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("location", response.headers)
        self.assertIsNotNone(self.app.state.store.get("pending", form["request"]))

    def test_independent_authorization_tabs_do_not_overwrite_each_other(self):
        first, _ = self.form()
        second, _ = self.form()
        for form in (first, second):
            response = self.client.post("/consent", data=form)
            self.assertTrue(self.callback_url(response).startswith(self.callback + "?"))

    def test_reload_keeps_previous_page_form_valid(self):
        form, _ = self.form()
        self.assertEqual(self.client.get("/consent", params={"request": form["request"]}).status_code, 200)
        response = self.client.post("/consent", data=form)
        self.assertTrue(self.callback_url(response).startswith(self.callback + "?"))

    def test_another_browser_loading_page_cannot_invalidate_owner_form(self):
        form, _ = self.form()
        with TestClient(self.app, base_url=self.config.public_url, follow_redirects=False) as other:
            self.assertEqual(other.get("/consent", params={"request": form["request"]}).status_code, 200)
        response = self.client.post("/consent", data=form)
        self.assertTrue(self.callback_url(response).startswith(self.callback + "?"))

    def test_missing_cookie_and_expiry_have_distinct_recovery(self):
        form, _ = self.form()
        self.client.cookies.clear()
        response = self.client.post("/consent", data=form)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["x-oauth-form-error"], "missing_cookie")
        self.assertIn('/consent?request=', response.text)
        with self.app.state.store.connect() as db:
            db.execute("UPDATE entries SET expires=0 WHERE kind='pending'")
        response = self.client.post("/consent", data=form)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["x-oauth-form-error"], "request_expired")
        self.assertNotIn('id="continue"', response.text)

    def test_form_cannot_be_reused_or_moved_to_another_request(self):
        first, _ = self.form()
        second, _ = self.form()
        moved = dict(first, request=second["request"])
        self.assertEqual(self.client.post("/consent", data=moved).status_code, 403)
        self.callback_url(self.client.post("/consent", data=first))
        self.assertEqual(self.client.post("/consent", data=first).status_code, 403)

    def test_token_bad_secret_pkce_redirect_and_replay(self):
        code, verifier = self.code()
        self.assertEqual(self.exchange(code, verifier, client_secret="bad").status_code, 401)
        self.assertEqual(self.exchange(code, "x" * 64).status_code, 400)
        self.assertEqual(self.exchange(code, verifier, redirect_uri="https://evil.example/").status_code, 400)
        self.assertEqual(self.exchange(code, verifier, resource="https://other.example/").status_code, 400)
        self.assertEqual(self.exchange(code, verifier).status_code, 200)
        self.assertEqual(self.exchange(code, verifier).status_code, 400)

    def test_basic_client_auth_without_form_credentials(self):
        code, verifier = self.code()
        credentials = base64.b64encode(f"{self.config.client_id}:{self.config.client_secret}".encode()).decode()
        response = self.client.post("/token", data=dict(grant_type="authorization_code", code=code,
            code_verifier=verifier, redirect_uri=self.callback), headers={"Authorization": "Basic " + credentials})
        self.assertEqual(response.status_code, 200, response.text)

    def test_authenticated_proxy_strips_credentials(self):
        token = self.tokens()["access_token"]
        response = self.client.post("/", json={"jsonrpc": "2.0", "method": "initialize", "id": 1}, headers={
            "Authorization": "Bearer " + token, "Cookie": "private=secret", "MCP-Protocol-Version": "2025-03-26",
            "X-Forwarded-For": "attacker", "Accept": "application/json, text/event-stream"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["result"]["ok"])
        self.assertEqual(response.headers["mcp-session-id"], "sample")
        upstream = self.forwarded[-1]
        self.assertEqual(str(upstream.url), self.config.upstream_url)
        self.assertNotIn("authorization", upstream.headers)
        self.assertNotIn("cookie", upstream.headers)
        self.assertNotIn("x-forwarded-for", upstream.headers)
        self.assertEqual(upstream.headers["mcp-protocol-version"], "2025-03-26")

    def test_secret_is_not_a_bearer_token(self):
        self.assertEqual(self.client.post("/", headers={"Authorization": "Bearer " + self.config.client_secret}).status_code, 401)

    def test_sse_stream_and_session_headers(self):
        token = self.tokens()["access_token"]
        observed = []

        class Events(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b'event: message\ndata: {"jsonrpc":"2.0",'
                yield b'"id":1,"result":{}}\n\n'

            async def aclose(self):
                observed.append("closed")

        async def upstream(request):
            observed.append(request.headers["mcp-session-id"])
            observed.append(request.headers["last-event-id"])
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Events())

        app = create_app(self.config, self.path, httpx.MockTransport(upstream))
        with TestClient(app, base_url=self.config.public_url) as client:
            response = client.get("/", headers={"Authorization": "Bearer " + token,
                "Accept": "text/event-stream", "MCP-Session-ID": "session-1", "Last-Event-ID": "event-1"})
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/event-stream", response.headers["content-type"])
            self.assertEqual(response.content, b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')
        self.assertEqual(observed, ["session-1", "event-1", "closed"])

    def test_wrong_audience_and_query_token_rejected(self):
        token = self.tokens()["access_token"]
        response = self.client.get("/", params={"access_token": token})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get("/", params={"access_token": token},
            headers={"Authorization": "Bearer " + token}).status_code, 400)
        row = self.app.state.store.get("access", token)
        row["payload"]["resource"] = "https://other.example/"
        self.app.state.store.put("access", token, row["payload"], row["expires"], row["family"])
        self.assertEqual(self.client.get("/", headers={"Authorization": "Bearer " + token}).status_code, 401)
        self.assertEqual(self.forwarded, [])

    def test_refresh_persistence_and_revocation(self):
        tokens = self.tokens()
        refreshed = self.refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 200)
        self.assertEqual(refreshed.json()["refresh_token"], tokens["refresh_token"])
        self.assertNotEqual(refreshed.json()["access_token"], tokens["access_token"])
        other = create_app(self.config, self.path, self.transport)
        with TestClient(other, base_url=self.config.public_url) as client:
            self.assertEqual(client.post("/", headers={"Authorization": "Bearer " + tokens["access_token"]}).status_code, 200)
        revoke = self.client.post("/revoke", data=dict(client_id=self.config.client_id,
            client_secret=self.config.client_secret, token=tokens["refresh_token"]))
        self.assertEqual(revoke.status_code, 200)
        for access in (tokens["access_token"], refreshed.json()["access_token"]):
            self.assertEqual(self.client.post("/", headers={"Authorization": "Bearer " + access}).status_code, 401)
        self.assertEqual(self.refresh(tokens["refresh_token"]).status_code, 400)

    def test_expired_tokens_and_codes(self):
        code, verifier = self.code()
        with self.app.state.store.connect() as db:
            db.execute("UPDATE entries SET expires=0 WHERE kind='code'")
        self.assertEqual(self.exchange(code, verifier).status_code, 400)
        token = self.tokens()
        with self.app.state.store.connect() as db:
            db.execute("UPDATE entries SET expires=0 WHERE kind IN ('access','refresh')")
        self.assertEqual(self.client.post("/", headers={"Authorization": "Bearer " + token["access_token"]}).status_code, 401)
        self.assertEqual(self.refresh(token["refresh_token"]).status_code, 400)

    def test_state_stores_only_token_hashes(self):
        token = self.tokens()
        database = self.path.read_bytes()
        for secret in (token["access_token"], token["refresh_token"], self.config.client_secret):
            self.assertNotIn(secret.encode(), database)

    def test_rotating_secret_invalidates_grants_and_stale_server(self):
        token = self.tokens()["access_token"]
        changed = replace(self.config, client_secret=secrets.token_urlsafe(48))
        app = create_app(changed, self.path, self.transport)
        self.assertEqual(self.client.post("/", headers={"Authorization": "Bearer " + token}).status_code, 503)
        with TestClient(app, base_url=self.config.public_url) as client:
            self.assertEqual(client.post("/", headers={"Authorization": "Bearer " + token}).status_code, 401)

    def test_rate_limit_cannot_be_bypassed_with_forwarded_ip(self):
        form, _ = self.form()
        for i in range(10):
            response = self.client.post("/consent", data=dict(form, client_secret="bad"),
                                        headers={"X-Forwarded-For": str(i)})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.post("/consent", data=form).status_code, 429)

    def test_wrong_host_and_oversized_oauth_body(self):
        self.assertEqual(self.client.get("/", headers={"Host": "evil.example"}).status_code, 400)
        self.assertEqual(self.client.post("/token", content=b"x" * 17000).status_code, 413)

    def test_security_headers_and_cookie(self):
        result, _ = self.begin()
        response = self.client.get(result.headers["location"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["referrer-policy"], "same-origin")
        self.assertIn("form-action 'self' " + self.callback + ";", response.headers["content-security-policy"])
        self.assertNotIn("*", response.headers["content-security-policy"])
        self.assertEqual(self.client.get("/.well-known/oauth-authorization-server").headers["referrer-policy"], "no-referrer")
        cookie = response.headers["set-cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=lax"):
            self.assertIn(flag, cookie)

    def test_config_rejects_external_upstream_and_wildcard(self):
        with self.assertRaises(ValueError):
            replace(self.config, upstream_url="http://evil.example:9191/")
        with self.assertRaises(ValueError):
            replace(self.config, redirect_uris=("https://example.com/*",))
        with self.assertRaises(ValueError):
            replace(self.config, public_url="http://blender.example.com")

    def test_diagnostics_do_not_log_credentials_query_or_tool_data(self):
        path = Path(self.tmp.name) / "diagnostics.jsonl"
        app = create_app(self.config, self.path, self.transport, diagnostic_path=path)
        marker = "sensitive-value-that-must-not-be-logged"
        with TestClient(app, base_url=self.config.public_url) as client:
            client.post("/?code=" + marker, headers={"Authorization": "Bearer " + marker},
                        json={"jsonrpc":"2.0", "id":marker, "method":"tools/call", "params":{"arguments":marker}})
            client.post("/token?state=" + marker, data={"client_secret":marker, "code":marker})
            client.get("/" + marker)
            client.get("/.well-known/oauth-protected-resource")
        log = path.read_text(encoding="utf-8")
        self.assertNotIn(marker, log)
        self.assertNotIn(self.config.client_secret, log)
        events = [json.loads(line) for line in log.splitlines()]
        self.assertEqual(events[0]["status"], 401)
        self.assertEqual(events[-1]["status"], 200)
        self.assertEqual(events[-1]["path"], "/.well-known/oauth-protected-resource")


if __name__ == "__main__":
    unittest.main()
