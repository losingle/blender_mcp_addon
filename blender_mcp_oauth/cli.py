"""Local configuration and server lifecycle. Never print secrets on normal startup."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import subprocess

from .config import Config
from .store import Store


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / ".private" / "config.json"


def protect_directory(directory):
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # Use the current user's SID, independent of account language or spaces.
        sid = subprocess.check_output([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ], text=True).strip()
        if not sid.startswith("S-1-"):
            raise RuntimeError("Cannot determine Windows owner SID")
        subprocess.run(["icacls.exe", str(directory), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True)
    else:
        directory.chmod(0o700)


def save_config(path, config):
    protect_directory(path.parent)
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps(asdict(config), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description="Independent OAuth gateway for Blender Lab MCP")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="Generate a fixed client and private configuration")
    initialize.add_argument("--public-url", required=True)
    initialize.add_argument("--client-id", default="gemini-blender")
    initialize.add_argument("--redirect-uri", action="append", default=[])
    initialize.add_argument("--upstream", default="http://127.0.0.1:9191/")
    serve = commands.add_parser("serve")
    serve.add_argument("--host", choices=["127.0.0.1", "::1"], default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9192)
    redirect = commands.add_parser("add-redirect", help="Register one exact HTTPS OAuth callback")
    redirect.add_argument("uri")
    show = commands.add_parser("show-client", help="Display client ID and optionally the secret locally")
    show.add_argument("--show-secret", action="store_true")
    commands.add_parser("revoke-all", help="Invalidate all authorization codes and tokens")
    commands.add_parser("rotate-secret", help="Generate a new secret and invalidate every existing grant")
    args = parser.parse_args()
    path = args.config.resolve()
    try:
        if args.command == "init":
            if path.exists():
                parser.error("Configuration already exists; refusing to overwrite it")
            config = Config(args.public_url, args.client_id, secrets.token_urlsafe(48),
                            tuple(args.redirect_uri), args.upstream)
            save_config(path, config)
            print(f"Created private configuration: {path}")
            print("Secret generated. Use show-client --show-secret in your own terminal to view it.")
            if not config.redirect_uris:
                print("OAuth is fail-closed until you register Gemini's exact callback with add-redirect.")
            return
        config = Config.load(path)
        store_path = path.parent / "oauth.sqlite3"
        if args.command == "serve":
            from urllib.parse import urlsplit
            if urlsplit(config.upstream_url).port == args.port:
                parser.error("Gateway and upstream must use different ports")
            protect_directory(path.parent)
            from .app import create_app
            import uvicorn
            print(f"OAuth gateway: {config.resource} -> {config.upstream_url}")
            print(f"Local listener: http://{args.host}:{args.port}/ (no anonymous MCP access)")
            if not config.redirect_uris:
                print("No callback registered; discovery works, but authorization is deliberately blocked.")
            # Disable access logs: OAuth codes, state and consent handles must not enter URL logs.
            uvicorn.run(create_app(config, store_path, diagnostic_path=path.parent / "diagnostics.jsonl"), host=args.host, port=args.port,
                        proxy_headers=False, access_log=False, log_level="info")
        elif args.command == "show-client":
            print("MCP URL:", config.resource)
            print("Client ID:", config.client_id)
            print("Scope: blender")
            print("Registered callbacks:", json.dumps(config.redirect_uris))
            if args.show_secret:
                print("Client Secret:", config.client_secret)
        elif args.command == "add-redirect":
            data = asdict(config)
            data["redirect_uris"] = tuple(dict.fromkeys((*config.redirect_uris, args.uri)))
            config = Config(**data)
            save_config(path, config)
            Store(store_path, config.fingerprint)
            print("Registered exact callback. Restart the gateway to load it; previous grants were revoked.")
        elif args.command == "revoke-all":
            Store(store_path, config.fingerprint).clear()
            print("All grants revoked. Clients must authorize again.")
        elif args.command == "rotate-secret":
            data = asdict(config)
            data["client_secret"] = secrets.token_urlsafe(48)
            config = Config(**data)
            save_config(path, config)
            Store(store_path, config.fingerprint).clear()
            print("Secret rotated. Restart the gateway and update Gemini's credentials.")
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
