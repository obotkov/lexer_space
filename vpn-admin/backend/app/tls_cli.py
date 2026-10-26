"""Certificate commands for install.sh, run inside the container:

    python -m app.tls_cli issue DOMAIN [EMAIL]   issue (or keep a valid) certificate and enable HTTPS
    python -m app.tls_cli status

The caller restarts the container afterwards so the admin starts serving HTTPS.
"""

import asyncio
import json
import sys

from . import tls


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "status":
        print(json.dumps(tls.status(), ensure_ascii=False, indent=2))
        return 0
    if command == "issue" and len(sys.argv) >= 3:
        email = sys.argv[3] if len(sys.argv) > 3 else ""
        try:
            result = asyncio.run(tls.issue(sys.argv[2], email, staging=False))
        except tls.TLSError as exc:
            print(exc, file=sys.stderr)
            return 1
        cert = result["certificate"] or {}
        print(f"Сертификат для {', '.join(cert.get('domains', []))} действует {cert.get('days_left')} дн.")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
