from flask import render_template, request, jsonify, redirect, url_for, abort, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import asc
from app import app, db
from app.database import User, Challenge, Lesson, Submission, MfaSetting
import typing as _t
import pyotp
import qrcode
import io


def admin_required():
    if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
        abort(403)

# --- Public pages ---
@app.route("/")
def index():
    return render_template("index.html")

# --- Auth ---
@app.route("/login", methods=["GET", "POST"])
def login_route():
    if request.method == "GET":
        return redirect(url_for("index") + "#login")
    data = request.get_json(silent=True) or request.form or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return redirect(url_for("index") + "?error=invalid#login")
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return redirect(url_for("index") + "?error=invalid#login")
    # If user has MFA enabled, require second factor
    mfa = MfaSetting.query.filter_by(user_id=user.id, enabled=True).first()
    if mfa:
        session["mfa_user_id"] = user.id
        return redirect(url_for("index") + "?mfa=required#login")
    login_user(user, remember=True)
    return redirect(url_for("index") + "#index")

@app.route("/register", methods=["POST"])
def register_route():
    data = request.get_json(silent=True) or request.form or {}
    secret = data.get("secret_code") or data.get("registration_code") or ""

    if secret != app.config.get("REGISTRATION_SECRET_CODE") and secret != app.config.get("ADMIN_CODE"):
        return redirect(url_for("index") + "?error=secret#register")
    
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return redirect(url_for("index") + "?error=invalid#register")
    if User.query.filter_by(username=username).first():
        return redirect(url_for("index") + "?error=exists#register")
    
    if secret == app.config.get("ADMIN_CODE"):
        is_admin = True
        
    user = User(username=username, is_admin=is_admin if 'is_admin' in locals() else False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)
    # Encourage MFA setup right after registering
    return redirect(url_for("index") + "#profile")

@app.route("/mfa-setup", methods=["POST"])
@login_required
def mfa_setup():
    # Deprecated minimal endpoint kept for backward compatibility
    return jsonify({"ok": True})

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index") + "#login")

@app.route("/?flag=<flag>", methods=["POST"])
@login_required
def flag_route(flag):

    # Handle flag submission
    flag = flag.strip()
    if not flag:
        return redirect(url_for("index") + "?error=missing_flag#flag")

    chal = Challenge.query.filter_by(flag_hash=flag).first()
    if not chal:
        return redirect(url_for("index") + "?error=invalid_flag#flag")

    # If we reach here, the flag is valid
    current_user.score += chal.points
    db.session.commit()
    return redirect(url_for("index") + "#index")

# --- API: list challenges ---
@app.get("/api/challenges/flat")
def api_list_challenges():
    items = Challenge.query.filter_by(is_active=True).order_by(asc(Challenge.id)).all()
    return jsonify([{
        "id": c.id,
        "name": c.title,
        "description": c.description or "",
        "points": c.points,
        "is_active": c.is_active,
    } for c in items])

# --- API: lessons with challenges ---
@app.get("/api/lessons")
def api_lessons():
    lessons = Lesson.query.order_by(asc(Lesson.id)).all()

    def serialize_chal(c: Challenge):
        return {
            "id": c.id,
            "title": c.title,
            "description": c.description or "",
            "points": int(c.points or 0),
            "is_active": bool(c.is_active),
        }

    payload = []
    for l in lessons:
        chals = Challenge.query.filter_by(lesson_id=l.id, is_active=True).order_by(asc(Challenge.id)).all()
        payload.append({
            "id": l.id,
            "title": l.title,
            "challenges": [serialize_chal(c) for c in chals],
        })

    # Ungrouped active challenges
    ungrouped = Challenge.query.filter_by(lesson_id=None, is_active=True).order_by(asc(Challenge.id)).all()
    if ungrouped:
        payload.append({
            "id": None,
            "title": "Ungrouped",
            "challenges": [serialize_chal(c) for c in ungrouped],
        })

    return jsonify(payload)

# --- API: status (for score display) ---
@app.get("/api/status")
def api_status():
    score_val = int(getattr(current_user, "score", 0) or 0) if current_user.is_authenticated else 0
    # Derive a simple experience metric from score (can be adjusted later)
    experience_val = score_val  # keep 1:1 for now
    mfa_enabled = False
    if current_user.is_authenticated:
        mfa_row = MfaSetting.query.filter_by(user_id=current_user.id, enabled=True).first()
        mfa_enabled = bool(mfa_row is not None)
    return jsonify({
        "loggedIn": current_user.is_authenticated,
        "username": getattr(current_user, "username", None) if current_user.is_authenticated else None,
        "score": score_val,
        "experience": experience_val,
        "isAdmin": getattr(current_user, "is_admin", False) if current_user.is_authenticated else False,
        "mfaEnabled": mfa_enabled,
    })

# --- API: submit flag (by challenge id) ---
@app.post("/api/challenges/<int:challenge_id>/submit")
@login_required
def api_submit_flag(challenge_id: int):
    data = request.get_json(silent=True) or request.form or {}
    flag = (data.get("flag") or "").strip()
    if not flag:
        return jsonify({"ok": False, "error": "Missing flag"}), 400
    chal = Challenge.query.get_or_404(challenge_id)
    if not chal.is_active:
        return jsonify({"ok": False, "error": "Challenge not active"}), 400
    if not chal.verify_flag(flag):
        return jsonify({"ok": True, "correct": False}), 200

    # Check if already solved to avoid double-scoring
    already = Submission.query.filter_by(user_id=current_user.id, challenge_id=chal.id).first()
    if already:
        return jsonify({
            "ok": True,
            "correct": True,
            "points": 0,
            "newScore": int(current_user.score or 0),
            "duplicate": True,
        }), 200

    # Record solve and update score once
    sub = Submission(user_id=current_user.id, challenge_id=chal.id)
    db.session.add(sub)
    current_user.score = int(current_user.score or 0) + int(chal.points or 0)
    db.session.commit()
    return jsonify({"ok": True, "correct": True, "points": chal.points, "newScore": int(current_user.score)}), 200

# --- API: leaderboard users ---
@app.get("/api/users")
def api_users():
    users = User.query.order_by(User.score.desc(), User.created_at.asc()).all()
    payload = []
    for u in users:
        score_val = int(u.score or 0)
        mfa_row = MfaSetting.query.filter_by(user_id=u.id, enabled=True).first()
        payload.append({
            "username": u.username,
            "score": score_val,
            "experience": score_val,  # derived for now
            "mfaEnabled": bool(mfa_row is not None),
        })
    return jsonify(payload)

# --- API: current user's solved challenges ---
@app.get("/api/me/solves")
@login_required
def api_me_solves():
    # Join submissions with challenges for details
    subs = (
        db.session.query(Submission, Challenge)
        .join(Challenge, Submission.challenge_id == Challenge.id)
        .filter(Submission.user_id == current_user.id)
        .order_by(Submission.created_at.desc())
        .all()
    )
    items = []
    for s, c in subs:
        items.append({
            "id": c.id,
            "title": c.title,
            "points": int(c.points or 0),
            "solvedAt": s.created_at.isoformat() + "Z",
        })
    return jsonify(items)

# --- MFA: complete login with token ---
@app.post("/login/mfa")
def login_mfa_verify():
    pending_user_id = session.get("mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("index") + "#login")
    user = User.query.get(pending_user_id)
    if not user:
        session.pop("mfa_user_id", None)
        return redirect(url_for("index") + "?error=invalid#login")
    data = request.get_json(silent=True) or request.form or {}
    token = (data.get("token") or "").strip()
    if not token:
        return redirect(url_for("index") + "?error=invalid#login")
    try:
        import pyotp
    except Exception:
        return redirect(url_for("index") + "?error=server#mfa")
    mfa = MfaSetting.query.filter_by(user_id=user.id, enabled=True).first()
    if not mfa or not mfa.secret:
        return redirect(url_for("index") + "?error=invalid#login")
    totp = pyotp.TOTP(mfa.secret)
    if not totp.verify(token, valid_window=1):
        return redirect(url_for("index") + "?error=invalid#login")
    session.pop("mfa_user_id", None)
    login_user(user, remember=True)
    return redirect(url_for("index") + "#index")

# --- MFA: setup endpoints ---
@app.route("/api/mfa/setup", methods=["GET", "POST"])
@login_required
def api_mfa_setup():
    mfa = MfaSetting.query.filter_by(user_id=current_user.id).first()
    if mfa and mfa.enabled:
        return jsonify({"ok": False, "error": "Already enabled"}), 400
    try:
        import pyotp  # type: ignore
    except Exception as e:
        return jsonify({"ok": False, "error": f"pyotp not available: {str(e)}"}), 400
    try:
        if not mfa:
            mfa = MfaSetting(user_id=current_user.id, secret=None, enabled=False)
            db.session.add(mfa)
        if not mfa.secret:
            mfa.secret = pyotp.random_base32()
            db.session.commit()
        issuer = "CTF Platform"
        totp = pyotp.TOTP(mfa.secret)
        otpauth = totp.provisioning_uri(name=current_user.username, issuer_name=issuer)
        qr_data_url = None
        try:
            import qrcode  # type: ignore
            import io, base64
            img = qrcode.make(otpauth)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        except Exception:
            qr_data_url = None
        return jsonify({
            "ok": True,
            "secret": mfa.secret,
            "manualCode": mfa.secret,
            "otpauth": otpauth,
            "qrDataUrl": qr_data_url,
            "qrCodeUrl": qr_data_url,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"MFA setup failed: {str(e)}"}), 500

@app.get("/api/diag/mfa")
def api_diag_mfa():
    """Lightweight diagnostics for MFA dependencies and table existence."""
    result = {"pyotp": None, "qrcode": None, "mfaTable": None}
    try:
        import pyotp  # type: ignore
        result["pyotp"] = getattr(pyotp, "__version__", "installed")
    except Exception as e:
        result["pyotp"] = f"missing: {e}" 
    try:
        import qrcode  # type: ignore
        result["qrcode"] = getattr(qrcode, "__version__", "installed")
    except Exception as e:
        result["qrcode"] = f"missing: {e}"
    try:
        # Simple check that the table exists by running a query
        db.session.query(MfaSetting.id).first()
        result["mfaTable"] = "ok"
    except Exception as e:
        result["mfaTable"] = f"error: {e}"
    return jsonify(result)

@app.post("/api/mfa/verify")
@login_required
def api_mfa_verify():
    data = request.get_json(silent=True) or request.form or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Missing token"}), 400
    try:
        import pyotp
    except Exception:
        return jsonify({"ok": False, "error": "Server missing MFA dependency"}), 500
    mfa = MfaSetting.query.filter_by(user_id=current_user.id).first()
    if not mfa or not mfa.secret:
        return jsonify({"ok": False, "error": "No pending secret"}), 400
    totp = pyotp.TOTP(mfa.secret)
    if not totp.verify(token, valid_window=1):
        return jsonify({"ok": True, "verified": False}), 200
    mfa.enabled = True
    db.session.commit()
    return jsonify({"ok": True, "verified": True}), 200

@app.post("/api/mfa/disable")
@login_required
def api_mfa_disable():
    mfa = MfaSetting.query.filter_by(user_id=current_user.id).first()
    if not mfa:
        return jsonify({"ok": True, "disabled": True}), 200
    mfa.enabled = False
    mfa.secret = None
    db.session.commit()
    return jsonify({"ok": True, "disabled": True}), 200

# --- Admin UI ---
@app.route("/admin")
@login_required
def admin_page():
    admin_required()
    challenges = Challenge.query.order_by(asc(Challenge.id)).all()
    lessons = Lesson.query.order_by(asc(Lesson.id)).all()
    return render_template("admin.html", challenges=challenges, lessons=lessons)

# --- Admin: create challenge ---
@app.post("/admin/challenges")
@login_required
def admin_create_challenge():
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    flag = (data.get("flag") or "").strip()
    if not title or not flag:
        return redirect(url_for("admin_page"))
    points = int(data.get("points") or 100)
    description = data.get("description") or ""
    # Lesson association (optional)
    lesson_id_val = data.get("lesson_id")
    lesson_id = None
    if lesson_id_val not in (None, "", "none"):
        try:
            lesson_id = int(lesson_id_val)
        except Exception:
            lesson_id = None

    chal = Challenge(title=title, description=description, points=points, is_active=True, lesson_id=lesson_id)
    chal.set_flag(flag)
    db.session.add(chal)
    db.session.commit()
    return redirect(url_for("admin_page"))

# --- Admin: update challenge ---
@app.post("/admin/challenges/<int:challenge_id>")
@login_required
def admin_update_challenge(challenge_id: int):
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    chal = Challenge.query.get_or_404(challenge_id)
    chal.title = (data.get("title") or chal.title).strip()
    if "description" in data:
        chal.description = data.get("description") or ""
    if data.get("points") not in (None, ""):
        chal.points = int(data.get("points"))
    chal.is_active = "is_active" in data and str(data.get("is_active")).lower() in ("1", "true", "yes", "on")
    # Lesson association (optional)
    if "lesson_id" in data:
        lesson_id_val = data.get("lesson_id")
        if lesson_id_val in (None, "", "none"):
            chal.lesson_id = None
        else:
            try:
                chal.lesson_id = int(lesson_id_val)
            except Exception:
                pass
    new_flag = (data.get("flag") or "").strip()
    if new_flag:
        chal.set_flag(new_flag)
    db.session.commit()
    return redirect(url_for("admin_page"))

# --- Admin: Lessons CRUD ---
@app.post("/admin/lessons")
@login_required
def admin_create_lesson():
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return redirect(url_for("admin_page"))
    l = Lesson(title=title)
    db.session.add(l)
    db.session.commit()
    return redirect(url_for("admin_page"))

@app.post("/admin/lessons/<int:lesson_id>")
@login_required
def admin_update_lesson(lesson_id: int):
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    l = Lesson.query.get_or_404(lesson_id)
    new_title = (data.get("title") or "").strip()
    if new_title:
        l.title = new_title
        db.session.commit()
    return redirect(url_for("admin_page"))

@app.post("/admin/lessons/<int:lesson_id>/delete")
@login_required
def admin_delete_lesson(lesson_id: int):
    admin_required()
    l = Lesson.query.get_or_404(lesson_id)
    # Prevent deleting a lesson with challenges to avoid cascade delete surprises
    if l.challenges and len(l.challenges) > 0:
        return redirect(url_for("admin_page"))
    db.session.delete(l)
    db.session.commit()
    return redirect(url_for("admin_page"))

# --- Admin: delete challenge ---
@app.post("/admin/challenges/<int:challenge_id>/delete")
@login_required
def admin_delete_challenge(challenge_id: int):
    admin_required()
    chal = Challenge.query.get_or_404(challenge_id)
    db.session.delete(chal)
    db.session.commit()
    return redirect(url_for("admin_page"))