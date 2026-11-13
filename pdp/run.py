"""Start the PDP with .env loaded. Run: pixi run pdp"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "pep"), str(ROOT / "pdp")]
import identity  # noqa: E402,F401  (loads .env before the server reads it)
import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8180, log_level="warning")
