"""Production WSGI entrypoint for PlexyTrack.

Served by waitress (see the Dockerfile). Importing this module runs the same
one-time startup initialization as ``python app.py`` and exposes the Flask
``app`` object (already wrapped with ProxyFix) for the WSGI server.

    waitress-serve --host=0.0.0.0 --port=5030 wsgi:app
"""

from app import app, startup_init

# Perform volume checks, credential/token loading and the security self-check
# before the server starts accepting requests.
startup_init()

__all__ = ["app"]
