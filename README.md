# Blender MCP OAuth extension

[简体中文使用说明](README.zh-CN.md)

This is an independent HTTP gateway, **not a Blender add-on installed inside Blender**.
It imports no Blender Lab internals and makes no changes to the official `blender_mcp` repository.

```
Gemini -- HTTPS + OAuth --> Cloudflare Tunnel --> OAuth gateway 127.0.0.1:9192
                                              --> official HTTP server 127.0.0.1:9191
                                              --> Blender TCP bridge 127.0.0.1:9876
```

## Start on Windows

Keep the Blender bridge and official HTTP server running as before. In another PowerShell:

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth init --public-url https://blender.taptot.io --client-id gemini-blender
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth show-client --show-secret
```

`init` runs only once and generates a random Client Secret. It saves configuration and opaque-token
state in `.private/`, excluded from version control and restricted to the current Windows user and
SYSTEM. Do not paste the secret into a chat, command-line argument or URL.

In Gemini's advanced/manual OAuth settings use the displayed Client ID / Secret and scope `blender`.
Register the **exact** callback URI supplied/used by Gemini:

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth add-redirect "https://oauth-redirect.googleusercontent.com/r/REPLACE_WITH_THE_ACTUAL_CALLBACK"
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth serve
```

If Gemini does not show its callback before connection, start the gateway and attempt connection
with manual credentials. The OAuth error page identifies an unregistered callback. Copy the
`redirect_uri` from the `/authorize` URL (URL-decode its value), inspect that it belongs to Google,
and register that exact URI using `add-redirect`. Do not paste the entire authorization URL.
Restart the gateway after editing configuration. No wildcard or automatic callback enrollment is
performed; an empty allowlist deliberately blocks authorization.

Change the existing Cloudflare route for **the entire `blender.taptot.io` hostname** to
`http://host.docker.internal:9192` (no path filter). Gemini still uses
`https://blender.taptot.io/`. Both `/.well-known/...` and OAuth routes must reach this gateway.
Remove any public routes that reach 9191 or 9876 directly, because those bypass OAuth.
The gateway and upstream bind loopback. Docker Desktop's host connectivity must work for 9192,
just as for the prior 9191 mapping. Do not publish the unauthenticated upstream separately.

During the first authorization, the consent page requests the same Client Secret. There is no
administrator account or separate password. This is intentionally a **single-owner, fixed-client**
setup: anyone holding this secret can authorize full Blender control. Do not use it as a multi-user
login system. OAuth protects access; it does not sandbox Blender Python or limit filesystem access.

Consent requests expire after 15 minutes. Each authorization has its own browser-bound cookie;
refreshing a page or opening another authorization cannot overwrite an existing form. On success,
a confirmation document returns to Gemini automatically and provides an explicit return link if
the browser blocks automatic navigation. Missing cookies and expired forms show distinct recovery
instructions. Old forms opened before this update should be replaced by a new connection from Gemini.

## Protocol and security boundaries

- MCP SDK 1.30 implements the OAuth authorization-code and S256 PKCE exchange; all MCP requests
  require a server-issued bearer access token. Client credentials alone are not accepted at `/`.
- Fixed confidential client; manual registration only. No `/register`, dynamic registration,
  password grant, or client-credentials grant. Metadata does not advertise unsupported flows.
- RFC 8414 authorization metadata and RFC 9728 protected-resource discovery at the domain root.
- Exact redirect matching, request state, browser CSRF binding, explicit secret-based consent,
  validated resource/audience, 2-minute single-use codes, 15-minute access tokens.
- Refresh grants expire after 14 days. Gemini Persistent Linking expects a stable refresh token,
  so refresh tokens are not rotated or extended on use. Confidential-client authentication is
  required on every refresh. Revocation invalidates the entire token family.
- SQLite persists state across restarts and stores only hashes of opaque token/code values.
  Configuration/credential changes invalidate existing grants. Keep the `.private` directory private.
- Bounded requests, global login/token rate limits, no request access logging, no external page
  assets and no-store responses. Consent pages use same-origin referrer policy so browser form POSTs
  retain their Origin while stripping referrers from external callbacks; other routes use no-referrer.
  The proxy forwards no OAuth credentials or cookies.
- Upstream is a fixed loopback HTTP URL. It never follows redirects or derives a target from requests.
  Streaming and MCP response headers are preserved.

Public endpoints: `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`,
`/authorize`, `/consent`, `/token`, `/revoke`. The MCP endpoint is `/`, not `/mcp`.

## Maintenance

```powershell
# Revoke all active grants immediately (server can stay running).
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth revoke-all
# Generate a new secret; stop/restart the gateway and update Gemini after this command.
uv --directory "F:\Mcps\blender_mcp_addon" run blender-mcp-oauth rotate-secret
# Run security and proxy tests without Blender.
uv --directory "F:\Mcps\blender_mcp_addon" run python -m unittest discover -s tests -v
```

Official Blender MCP updates are independent. This gateway needs updates only if its public HTTP
transport changes. Back up `.private` securely if persistent grants must survive migration; deleting
the token database signs clients out. Run one gateway worker/process per configuration.

## Acceptance checks

Anonymous MCP requests must return `401` with `WWW-Authenticate`; metadata must return `200`;
unknown callbacks, bad secrets, incorrect PKCE and reused codes must fail; valid authorization
must permit an MCP `initialize` and `tools/list`; revocation must immediately block the token.
Gemini's actual browser callback/login flow requires final interactive verification by the owner.

References: [Google OAuth guide](https://developers.google.com/connected-apps/mcp/oauth),
[MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

Protocol diagnostics are stored in .private/diagnostics.jsonl (bounded rotation). They record only known paths, methods, status codes and protocol labels, excluding query strings, credentials and tool arguments.
