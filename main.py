import os
from app import app

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = bool(app.config.get('DEVELOPMENT_MODE', False))
    app.run(host=host, port=port, debug=debug)
