from app import db, app
from flask_login import UserMixin
from . import app as flask_app, db
from datetime import datetime
from . import db, bcrypt, app

def init_db():
    # Use the Flask app’s context
    with app.app_context():
        db.create_all()

class User(db.Model, UserMixin):
    __tablename__ = "users"  # ensure table name matches FK references
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    # email = db.Column(db.String(255), unique=False, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # MFA / TOTP Secret 
    mfa_secret = db.Column(db.String(32), nullable=True)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

class Lesson(db.Model):
    __tablename__ = "lessons"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    challenges = db.relationship(
        "Challenge",
        backref="lesson",
        lazy=True,
        cascade="all, delete",
    )

class Challenge(db.Model):
    __tablename__ = "challenges"
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey("lessons.id"), nullable=True)
    title = db.Column(db.String(128), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, nullable=False, default=100)
    flag_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_flag(self, flag: str):
        self.flag_hash = bcrypt.generate_password_hash(flag).decode("utf-8")

    def verify_flag(self, submitted: str) -> bool:
        return bcrypt.check_password_hash(self.flag_hash, submitted)

class Submission(db.Model):
    __tablename__ = "submissions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Fix FK target to match Challenge.__tablename__
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "challenge_id", name="uq_user_chal"),)

class MfaSetting(db.Model):
    __tablename__ = "mfa_settings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True)
    secret = db.Column(db.String(64), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Utility: create or update a challenge and set its flag
def create_or_update_challenge(name: str, description: str, flag: str, points: int = 100, is_active: bool = True):
    with app.app_context():
        chal = Challenge.query.filter_by(name=name).first()
        if not chal:
            chal = Challenge(name=name)
        chal.description = description
        chal.points = points
        chal.is_active = is_active
        chal.set_flag(flag)
        db.session.add(chal)
        db.session.commit()
        return chal.id

