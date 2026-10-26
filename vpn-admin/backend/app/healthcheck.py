"""Docker HEALTHCHECK: the admin answers on PORT over HTTP or HTTPS (self-check skips verification)."""

import os
import ssl
import sys
import urllib.request

port = os.getenv("PORT", "8080")
for scheme in ("https", "http"):
    try:
        context = ssl._create_unverified_context() if scheme == "https" else None
        urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/api/health", timeout=4, context=context)
        sys.exit(0)
    except Exception:  # noqa: BLE001 — any failure means "try the other scheme"
        continue
sys.exit(1)
