# Blender MCP OAuth 使用说明

独立模块已安装在 `F:\Mcps\blender_mcp_addon`。官方 `F:\Mcps\blender_mcp` 源码未修改，两边分别使用自己的 Python 虚拟环境。此模块是外部 HTTP 网关，无需安装进 Blender。

## Gemini 填写项

| 项目 | 内容 |
| --- | --- |
| MCP 地址 | `https://blender.taptot.io/` |
| Client ID | `gemini-blender` |
| Client Secret | 使用下面的命令在本机终端查看 |
| Scope（如果有此字段） | `blender` |
| 已登记回调 | `https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-be98f6a602f8bc4511558d38` |

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run --locked blender-mcp-oauth show-client --show-secret
```

在 Gemini 中保存 Client ID / Secret 后，首次连接会打开授权页。输入同一个 Client Secret 并确认授权即可，没有额外的管理员账号或密码。Secret 不应贴入聊天、URL 或 Git。

点击一次确认后会显示“授权已确认”，随后自动返回 Gemini。如果停留在确认页，点击“返回 Gemini”即可，不要返回旧表单反复提交。每次授权请求有效期为 15 分钟；各授权页使用独立 Cookie，刷新或多标签页不会互相覆盖。

授权页授予的是完整 Blender MCP 权限，包括执行 Python。当前方案用于单人、固定客户端；持有该 Secret 的人可以授权访问。

## 运行链路

```text
Gemini
  → https://blender.taptot.io/（Cloudflare HTTPS）
  → http://host.docker.internal:9192（独立 OAuth 网关）
  → http://127.0.0.1:9191/（官方 MCP HTTP）
  → 127.0.0.1:9876（Blender 内部桥接）
```

Cloudflare 已切换到 `9192`，整条域名包括 OAuth 和 `.well-known` 路由都经过网关。保持 `9191`、`9876` 只用于本机通信，不另设公网直连路由。

## 重启后的启动顺序

目前 OAuth 网关已在后台运行；本次没有配置开机自启。重新启动电脑后，需要依次启动以下服务。

1. 打开 Blender，启动原有插件的 TCP 服务（`9876`）。
2. 启动官方 HTTP 服务：

```powershell
$env:BLENDER_MCP_HOST = "127.0.0.1"
$env:BLENDER_MCP_PORT = "9876"
$env:BLENDER_PATH = "D:\Program Files\Blender Foundation\Blender 5.2\blender.exe"
uv --directory "F:\Mcps\blender_mcp\mcp" run blender-mcp --transport http --host 127.0.0.1 --port 9191
```

3. 在另一个 PowerShell 中启动 OAuth 网关：

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run --locked blender-mcp-oauth serve
```

4. 确保 Docker 中的 Cloudflare Tunnel 正常运行。

正在运行时无需重复启动。前台启动的服务可使用 `Ctrl+C` 停止。

## 模块和维护

| 文件 | 作用 |
| --- | --- |
| `blender_mcp_oauth/config.py` | 公网地址、固定客户端、精确回调配置 |
| `blender_mcp_oauth/provider.py` | OAuth 授权码、访问令牌和刷新流程 |
| `blender_mcp_oauth/consent.py` | 独立浏览器表单会话、成功确认页和错误恢复 |
| `blender_mcp_oauth/store.py` | SQLite 状态、令牌哈希、撤销 |
| `blender_mcp_oauth/proxy.py` | 验证令牌并转发 MCP HTTP / SSE |
| `blender_mcp_oauth/app.py` | OAuth 路由、授权确认页、请求保护 |
| `blender_mcp_oauth/cli.py` | 初始化、启动和凭据管理命令 |
| `.private/config.json` | 私有配置，包含 Client Secret |
| `.private/oauth.sqlite3` | 持久化授权状态 |
| `uv.lock` | 独立锁定依赖版本 |

`.private` 已限制为当前 Windows 用户和 SYSTEM 可访问，并加入 `.gitignore`。令牌值以哈希保存；配置文件中的客户端 Secret 需要保密。

访问令牌有效期 15 分钟，刷新令牌有效期 14 天；到期后重新授权。授权状态可跨网关重启保留。下列命令立即撤销所有连接，无需重启：

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run --locked blender-mcp-oauth revoke-all
```

如果 Secret 泄露，可轮换后重启网关，并更新 Gemini 配置：

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run --locked blender-mcp-oauth rotate-secret
```

官方更新通常只需更新原仓库。网关只依赖官方对外的 MCP HTTP 协议；若官方更改监听端口或接口路径，再更新 `.private/config.json` 的 `upstream_url` 并重启。无需给官方源码反复打补丁。

## 已完成的验证

2026-11-13：30 项自动化测试通过。已通过实际公网 HTTPS 验证匿名请求 `401`、发现接口 `200`、授权码 + PKCE 交换、MCP 初始化与工具列表、令牌刷新和撤销。另用实际 Edge 验证多标签页、刷新后提交、自动返回和手动“返回 Gemini”两种路径，以及授权码交换。测试授权已撤销。

已修复首次授权时的 `Invalid form origin`：授权页使用 `same-origin` Referrer-Policy，避免 Chromium 因 `no-referrer` 在表单 POST 中发送 `Origin: null`；外部回调不携带 Referrer，Origin/CSRF 校验继续保留。若仍停留在旧页面，请关闭它，从 Gemini 重新发起连接。无需更换 Client ID/Secret。

已修复刷新及多标签页覆盖校验状态所导致的 `Invalid or expired authorization form`。过期请求、缺少 Cookie 和表单不匹配会显示不同的恢复提示。打开在此次更新之前的旧表单需要关闭，从 Gemini 重新发起连接。

回调地址以 Gemini 当前应用配置显示的值为准。重新连接原配置通常沿用原地址；删除并重新创建应用可能生成新地址，需要使用 `add-redirect` 登记完整新地址并重启网关。

Gemini 自身的浏览器授权及关联应用状态，需要在 Gemini 界面完成首次连接后确认；当前结果未将通用 OAuth 联调等同于 Gemini 已绑定成功。

```powershell
uv --directory "F:\Mcps\blender_mcp_addon" run --locked python -m unittest discover -s tests -v
```
