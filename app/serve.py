"""Entry point: starts uvicorn, with HTTPS when a certificate is installed (see app/tls.py)."""
import os

import uvicorn

from . import tls


def main():
    kw = {}
    if tls.enabled():
        p = tls.paths()
        kw = {"ssl_certfile": str(p[0]), "ssl_keyfile": str(p[1])}
    uvicorn.run("app.main:app", host=os.environ.get("BIND_HOST", "0.0.0.0"),
                port=int(os.environ.get("PORT", "8080")), access_log=False, **kw)


if __name__ == "__main__":
    main()
