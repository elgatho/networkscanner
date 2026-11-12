"""Entry point: starts uvicorn, with HTTPS when a certificate is installed (see app/tls.py).

When HTTPS is active, a small plain-HTTP listener on HTTP_REDIRECT_PORT (default 80)
answers every request with a 308 redirect to the same path on https://<host>:<PORT>.
Set HTTP_REDIRECT_PORT=0 to disable it.
"""
import os
import threading

import uvicorn

from . import tls


def _https_location(scope, port: int) -> str:
    host = "localhost"
    for k, v in scope.get("headers", []):
        if k == b"host":
            host = v.decode("latin-1")
            break
    # strip the port from the Host header (IPv6 literals are bracketed)
    if host.startswith("["):
        hostname = host[: host.index("]") + 1]
    else:
        hostname = host.rsplit(":", 1)[0] if ":" in host else host
    netloc = hostname if port == 443 else f"{hostname}:{port}"
    qs = scope.get("query_string", b"").decode("latin-1")
    return f"https://{netloc}{scope.get('path', '/')}" + (f"?{qs}" if qs else "")


async def redirect_app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    location = _https_location(scope, int(os.environ.get("PORT", "8080")))
    await send({"type": "http.response.start", "status": 308,
                "headers": [(b"location", location.encode("latin-1")),
                            (b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})


def main():
    host = os.environ.get("BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    kw = {}
    if tls.enabled():
        p = tls.paths()
        kw = {"ssl_certfile": str(p[0]), "ssl_keyfile": str(p[1])}
        redirect_port = int(os.environ.get("HTTP_REDIRECT_PORT", "80"))
        if redirect_port and redirect_port != port:
            threading.Thread(
                target=uvicorn.run,
                kwargs={"app": redirect_app, "host": host, "port": redirect_port,
                        "access_log": False, "log_level": "warning"},
                daemon=True,
            ).start()
    uvicorn.run("app.main:app", host=host, port=port, access_log=False, **kw)


if __name__ == "__main__":
    main()
