import os
from . import app

if __name__ == "__main__":
    # Listen on all interfaces so it's reachable from Docker/other hosts
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = bool(app.config.get("DEVELOPMENT_MODE", False))

    # Optional TLS support
    ssl_context = None
    if str(os.environ.get("SSL_ADHOC", "")).lower() in ("1", "true", "yes", "on"):
        ssl_context = "adhoc"  # For development/testing only
    else:
        cert_file = os.environ.get("SSL_CERT_FILE")
        key_file = os.environ.get("SSL_KEY_FILE")
        if cert_file and key_file:
            ssl_context = (cert_file, key_file)

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
