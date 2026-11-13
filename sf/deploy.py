"""
Deploy the Snowflake objects. Placeholders ${X} in sf/*.sql are
replaced from .env / environment. Generates the sync service key pair on
first run (.cache/sync_key.p8, git-ignored).

Run: pixi run sf-deploy        (uses SNOWFLAKE_CONNECTION from .env)
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pep"))
import identity  # noqa: E402,F401  (loads .env)

KEY = ROOT / ".cache" / "sync_key.p8"
CONN = os.environ.get("SNOWFLAKE_CONNECTION", "default")


def ensure_key() -> str:
    KEY.parent.mkdir(exist_ok=True)
    if not KEY.exists():
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        KEY.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        KEY.chmod(0o600)
    k = serialization.load_pem_private_key(KEY.read_bytes(), None)
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return "".join(l for l in pub.splitlines() if "-----" not in l)


def sql(q: str) -> str:
    r = subprocess.run(["snow", "sql", "-c", CONN, "--format", "JSON", "-q", q],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr or r.stdout)
    return r.stdout


def main() -> None:
    import json
    me = json.loads(sql("SELECT CURRENT_USER() U"))[0]["U"]
    os.environ.setdefault("ADMIN_USER", me)
    os.environ.setdefault("DEMO_SNOWFLAKE_USER", me)
    os.environ["SYNC_PUBLIC_KEY"] = ensure_key()
    for k in ("DEMO_USER_UPN", "SENTINEL_SP_OID", "GENIE_SP_OID"):
        os.environ[f"{k}_UPPER"] = os.environ[k].upper()
    files = sys.argv[1:] or sorted(str(p) for p in (ROOT / "sf").glob("0*.sql"))
    for f in files:
        text = Path(f).read_text()
        text = re.sub(r"\$\{(\w+)\}", lambda m: os.environ[m.group(1)], text)
        tmp = ROOT / ".cache" / Path(f).name
        tmp.write_text(text)
        print(f"-> {Path(f).name}")
        r = subprocess.run(["snow", "sql", "-c", CONN, "-f", str(tmp)], capture_output=True, text=True)
        if r.returncode:
            print(r.stdout[-3000:], r.stderr[-3000:])
            sys.exit(1)
    print("deployed")


if __name__ == "__main__":
    main()
