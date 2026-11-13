"""Browser-bound consent forms, isolated per authorization request."""
import html
import hmac
import math
import re
import secrets
import time
from urllib.parse import urlencode

from starlette.responses import HTMLResponse

from .store import digest

AUTHORIZATION_SECONDS = 900


class ConsentForms:
    def __init__(self, store):
        self.store = store

    @staticmethod
    def cookie_name(handle):
        return "__Host-blender-oauth-" + digest(handle)[:24]

    def issue(self, handle, cookie, expires):
        # Refreshes reuse this browser's form. A different browser receives a
        # separate form and cannot invalidate the first browser's CSRF binding.
        row = self.store.get("form", cookie) if re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie) else None
        if not row or row["payload"].get("request_hash") != digest(handle):
            cookie = secrets.token_urlsafe(32)
            self.store.put("form", cookie, {"request_hash": digest(handle)}, expires)
        return cookie, max(1, math.ceil(expires - time.time()))

    def check(self, handle, csrf, cookie):
        if not cookie:
            return "missing_cookie"
        if not csrf or not hmac.compare_digest(csrf.encode(), cookie.encode()):
            return "form_mismatch"
        row = self.store.get("form", csrf)
        if not row:
            return "form_expired"
        if not hmac.compare_digest(row["payload"].get("request_hash", ""), digest(handle)):
            return "form_mismatch"
        return None

    def consume(self, csrf):
        self.store.get("form", csrf, consume=True)


def result_page(title, message, url=None, label="返回授权页", auto=False, status=200, reason=None):
    target = html.escape(url or "", quote=True)
    refresh = f'<meta http-equiv="refresh" content="1;url={target}">' if auto and url else ""
    link = f'<p><a id="continue" href="{target}" referrerpolicy="no-referrer">{html.escape(label)}</a></p>' if url else ""
    content = f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{refresh}
<title>{html.escape(title)}</title><style>
body{{font:16px/1.7 system-ui,sans-serif;background:#f5f5f2;color:#202826;padding:8vh 20px}}
main{{max-width:520px;margin:auto;background:white;padding:32px;border-radius:16px}}
a{{display:inline-block;padding:10px 20px;border-radius:7px;background:#255741;color:white;text-decoration:none}}
</style><main><h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>{link}</main></html>'''
    response = HTMLResponse(content, status_code=status)
    if reason:
        response.headers["X-OAuth-Form-Error"] = reason
    return response


def form_error(reason, handle, active):
    messages = {
        "request_expired": "本次授权已完成或超过 15 分钟有效期。请返回 Gemini 查看连接状态；若尚未连接，请重新发起授权。",
        "missing_cookie": "浏览器没有带回授权 Cookie。请允许此网站使用 Cookie，然后重新打开授权页。",
        "form_mismatch": "此表单与当前浏览器会话不匹配。请重新打开授权页后再确认。",
        "form_expired": "此表单已失效。请重新打开授权页后再确认。",
    }
    retry = "/consent?" + urlencode({"request": handle}) if active else None
    return result_page("请重新打开授权页", messages[reason], retry, status=403, reason=reason)
