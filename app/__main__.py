from . import app

if __name__ == "__main__":
    app.run(debug=app.config.get("PRODUCTION_MODE", False))
