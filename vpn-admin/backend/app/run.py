"""Container entrypoint: starts uvicorn over HTTPS when a Let's Encrypt certificate
is enabled (see tls.py), plain HTTP otherwise.

The admin runs on the host network, so it binds BIND_ADDR:PORT from .env directly.
Proxy headers (real client IP) are trusted only from FORWARDED_ALLOW_IPS.
"""

import logging
import os

import uvicorn

from . import tls

logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(name)s %(message)s")


def main() -> None:
    options: dict = {}
    if tls.should_serve_tls():
        options = {"ssl_certfile": str(tls.CERT_FILE), "ssl_keyfile": str(tls.KEY_FILE)}
        os.environ["TLS_ACTIVE"] = "1"
        logging.info("HTTPS on, certificate for %s", ", ".join(tls.cert_info()["domains"]))
    elif tls.load_config().get("enabled"):
        logging.warning("HTTPS is enabled but the certificate is missing or expired: starting over HTTP")
    uvicorn.run(
        "app.main:app",
        host=os.getenv("BIND_ADDR", "0.0.0.0"),
        port=int(os.getenv("PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        **options,
    )


if __name__ == "__main__":
    main()
