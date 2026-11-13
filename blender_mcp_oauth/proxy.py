"""Transport-only bridge: validate tokens, then stream to the fixed local MCP URL."""
import httpx
from starlette.responses import JSONResponse, StreamingResponse


def create_proxy(config, provider):
    async def proxy(request):
        authorization = request.headers.get("authorization", "")
        value = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        token = await provider.load_access_token(value) if value and len(value) < 512 else None
        if not token or token.resource != config.resource or "blender" not in token.scopes:
            return JSONResponse({"error": "invalid_token"}, status_code=401, headers={
                "WWW-Authenticate": 'Bearer resource_metadata="' + config.public_url
                + '/.well-known/oauth-protected-resource", scope="blender"',
            })
        if "access_token" in request.query_params:
            return JSONResponse({"error": "invalid_request",
                "error_description": "Query-string access tokens are not supported"}, status_code=400)
        headers = {k: v for k, v in request.headers.items() if k.lower() in {
            "accept", "content-type", "mcp-protocol-version", "mcp-session-id", "last-event-id",
        }}
        try:
            upstream_request = request.app.state.http.build_request(
                request.method, config.upstream_url, params=request.query_params,
                headers=headers, content=await request.body(),
            )
            upstream = await request.app.state.http.send(upstream_request, stream=True)
        except httpx.HTTPError:
            return JSONResponse({"error": "upstream_unavailable",
                "error_description": "Blender MCP HTTP upstream is unavailable"}, status_code=502)
        # Neither OAuth credentials nor browser cookies are sent to Blender.
        response_headers = {k: v for k, v in upstream.headers.items() if k.lower() in {
            "content-type", "content-encoding", "mcp-session-id", "retry-after",
        }}

        async def stream():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(stream(), status_code=upstream.status_code, headers=response_headers)

    return proxy
