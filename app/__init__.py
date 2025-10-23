from flask import Flask
from pathlib import Path
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
import os

# --- App Initialization ---
app = Flask(__name__)
print("[Startup] Setting application configuration...")
app.config['DEVELOPMENT_MODE'] = False # Set to True for development
app.config['REGISTRATION_SECRET_CODE'] = 'your_secret_code'  # Change in production
app.config['SECRET_KEY'] = 'your_secret_key'                 # Change in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADMIN_CODE'] = 'admin_secret_code'  # Change in production

# --- Database Path Configuration ---
base_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(base_dir, 'data')
os.makedirs(data_dir, exist_ok=True)
db_fs_path = os.path.join(data_dir, 'dev_database.db' if app.config['DEVELOPMENT_MODE'] else 'prod_database.db')
Path(db_fs_path).touch(exist_ok=True)
db_uri_path = db_fs_path.replace('\\', '/')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_uri_path}'
print(("[DEV]" if app.config['DEVELOPMENT_MODE'] else "[PROD]") + f"[Startup] Using SQLite DB: {app.config['SQLALCHEMY_DATABASE_URI']}")

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "index"

@login_manager.unauthorized_handler
def _unauth():
    from flask import request, jsonify, redirect, url_for
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return redirect(url_for("index") + "#login")

# Import models and routes after extensions
from .database import User, Challenge, init_db

@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

from . import routes

# Create tables
init_db()
