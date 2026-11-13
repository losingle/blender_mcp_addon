"""Persistent, hashed opaque credentials; atomic single-use grants."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import time


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class ConfigurationChanged(RuntimeError):
    pass


class Store:
    def __init__(self, path: Path, fingerprint: str):
        self.path = path
        self.fingerprint = fingerprint
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect(check_config=False) as db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            db.execute("""CREATE TABLE IF NOT EXISTS entries (
                kind TEXT, key TEXT, payload TEXT, expires REAL, family TEXT,
                PRIMARY KEY (kind,key))""")
            db.execute("CREATE INDEX IF NOT EXISTS families ON entries(family)")
            old = db.execute("SELECT value FROM meta WHERE key='config'").fetchone()
            if old and old[0] != fingerprint:
                db.execute("DELETE FROM entries")
            db.execute("INSERT OR REPLACE INTO meta VALUES ('config',?)", (fingerprint,))

    @contextmanager
    def connect(self, check_config=True):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            if check_config:
                current = db.execute("SELECT value FROM meta WHERE key='config'").fetchone()
                if not current or current[0] != self.fingerprint:
                    raise ConfigurationChanged("Configuration changed; restart the OAuth gateway")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def put(self, kind, key, payload, expires, family=""):
        with self.connect() as db:
            db.execute("DELETE FROM entries WHERE expires < ?", (time.time(),))
            count = db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            if count >= 10000:
                raise RuntimeError("OAuth state capacity exceeded")
            db.execute("INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?)",
                       (kind, digest(key), json.dumps(payload), expires, family))

    def get(self, kind, key, consume=False):
        with self.connect() as db:
            row = db.execute("SELECT * FROM entries WHERE kind=? AND key=? AND expires>=?",
                             (kind, digest(key), time.time())).fetchone()
            if not row:
                return None
            if consume:
                db.execute("DELETE FROM entries WHERE kind=? AND key=?", (kind, digest(key)))
            return {"payload": json.loads(row["payload"]), "expires": row["expires"], "family": row["family"]}

    def revoke(self, family):
        with self.connect() as db:
            db.execute("DELETE FROM entries WHERE family=?", (family,))

    def exchange(self, access, refresh, payload, access_expires, refresh_expires, family,
                 *, code=None, previous_refresh=None):
        """Consume a code/check a refresh and mint its tokens in one transaction."""
        with self.connect() as db:
            now = time.time()
            db.execute("DELETE FROM entries WHERE expires < ?", (now,))
            kind, value = ("code", code) if code is not None else ("refresh", previous_refresh)
            if value is not None:
                row = db.execute("SELECT * FROM entries WHERE kind=? AND key=? AND expires>=?",
                                 (kind, digest(value), now)).fetchone()
                if not row or json.loads(row["payload"])["client_id"] != payload["client_id"]:
                    return False
                if kind == "refresh" and row["family"] != family:
                    return False
                if kind == "code":
                    db.execute("DELETE FROM entries WHERE kind='code' AND key=?", (digest(value),))
            if db.execute("SELECT COUNT(*) FROM entries").fetchone()[0] >= 10000:
                raise RuntimeError("OAuth state capacity exceeded")
            for token_kind, token_value, expiry in (("access", access, access_expires),
                                                     ("refresh", refresh, refresh_expires)):
                db.execute("INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?)",
                           (token_kind, digest(token_value), json.dumps(payload), expiry, family))
            return True

    def clear(self):
        with self.connect() as db:
            db.execute("DELETE FROM entries")
