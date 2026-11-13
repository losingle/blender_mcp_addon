"""Explicit public origin, fixed client credentials, and exact callback allowlist."""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    public_url: str
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uris: tuple[str, ...] = ()
    upstream_url: str = "http://127.0.0.1:9191/"
    access_seconds: int = 900
    refresh_seconds: int = 1209600

    def __post_init__(self):
        origin = self.public_url.rstrip("/")
        u = urlsplit(origin)
        if (u.scheme != "https" or not u.hostname or u.username or u.password
                or u.path or u.query or u.fragment or u.port not in (None, 443)):
            raise ValueError("public_url must be an HTTPS origin without a path, query or credentials")
        object.__setattr__(self, "public_url", origin)
        if not self.client_id or len(self.client_id) > 128:
            raise ValueError("client_id must contain 1–128 characters")
        if len(self.client_secret) < 32 or len(self.client_secret) > 512:
            raise ValueError("Use a randomly generated Client Secret of at least 32 characters")
        if not (60 <= self.access_seconds <= 3600 and 600 <= self.refresh_seconds <= 2592000):
            raise ValueError("Invalid token lifetime")
        upstream = urlsplit(self.upstream_url)
        if (upstream.scheme != "http" or upstream.hostname not in ("127.0.0.1", "localhost", "::1")
                or not upstream.port or upstream.username or upstream.password
                or upstream.query or upstream.fragment):
            raise ValueError("upstream_url must be an HTTP service on loopback with an explicit port")
        for uri in self.redirect_uris:
            r = urlsplit(uri)
            if (r.scheme != "https" or not r.hostname or r.username or r.password
                    or r.fragment or "*" in uri):
                raise ValueError("Callbacks must be exact HTTPS URLs without wildcards or fragments")

    @property
    def resource(self):
        return self.public_url + "/"

    @property
    def fingerprint(self):
        # Changing identity, credentials, callback policy or origin invalidates existing grants.
        data = [self.public_url, self.client_id, self.client_secret, self.redirect_uris]
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()

    def valid_resource(self, resource):
        return resource is None or resource in (self.public_url, self.resource)

    @classmethod
    def load(cls, path: Path):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["redirect_uris"] = tuple(data.get("redirect_uris", []))
        return cls(**data)
