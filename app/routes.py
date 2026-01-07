from flask import render_template, request, jsonify, redirect, url_for, abort, session, send_file
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import asc
from app import app, db
from app.database import User, Challenge, Lesson, Submission, MfaSetting, ChallengeSecret, AttemptLog, Team, TeamMembership
from datetime import datetime, timedelta
import typing as _t
import pyotp
import qrcode
import io
import os
from werkzeug.utils import secure_filename


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
    # Challenges completed count
    completed_val = 0
    if current_user.is_authenticated:
        try:
            completed_val = db.session.query(Submission).filter_by(user_id=current_user.id).count()
        except Exception:
            completed_val = 0
    mfa_enabled = False
    if current_user.is_authenticated:
        mfa_row = MfaSetting.query.filter_by(user_id=current_user.id, enabled=True).first()
        mfa_enabled = bool(mfa_row is not None)
    # Determine avatar URL if available
    def _avatar_url_for(user_id: int) -> _t.Optional[str]:
        base_dir = os.path.join(app.root_path, 'data', 'profile_images')
        for ext in ("png", "jpg", "jpeg"):
            p = os.path.join(base_dir, f"{user_id}.{ext}")
            if os.path.exists(p):
                return f"/profile_images/{user_id}"
        return None

    return jsonify({
        "loggedIn": current_user.is_authenticated,
        "username": getattr(current_user, "username", None) if current_user.is_authenticated else None,
        "score": score_val,
        "completed": completed_val,
        "isAdmin": getattr(current_user, "is_admin", False) if current_user.is_authenticated else False,
        "mfaEnabled": mfa_enabled,
        "avatarUrl": _avatar_url_for(current_user.id) if current_user.is_authenticated else None,
    })

# --- API: submit flag (by challenge id) ---
@app.post("/api/challenges/<int:challenge_id>/submit")
@login_required
def api_submit_flag(challenge_id: int):
    data = request.get_json(silent=True) or request.form or {}
    # --- Brute-force guard ---
    def _client_ip() -> str:
        # Rely on ProxyFix having applied correct headers when behind proxy
        return request.headers.get('X-Forwarded-For', request.remote_addr or '')

    def _blocked_and_retry_after(user_id: int, chal_id: int) -> tuple[bool, int]:
        window_seconds = int(app.config.get('FLAG_MAX_ATTEMPTS_WINDOW_SECONDS', 60))
        max_attempts = int(app.config.get('FLAG_MAX_ATTEMPTS_PER_MINUTE', 5))
        since = datetime.utcnow() - timedelta(seconds=window_seconds)
        q = AttemptLog.query.filter(
            AttemptLog.user_id == user_id,
            AttemptLog.challenge_id == chal_id,
            AttemptLog.success.is_(False),
            AttemptLog.created_at >= since,
        )
        count = q.count()
        if count >= max_attempts:
            oldest = q.order_by(AttemptLog.created_at.asc()).first()
            retry_after = max(1, window_seconds - int((datetime.utcnow() - oldest.created_at).total_seconds())) if oldest else window_seconds
            return True, retry_after
        return False, 0

    blocked, retry_after = _blocked_and_retry_after(current_user.id, challenge_id)
    if blocked:
        return jsonify({
            "ok": False,
            "error": "Too many attempts. Please wait before trying again.",
            "retryAfter": retry_after,
        }), 429
    flag = (data.get("flag") or "").strip()
    if not flag:
        return jsonify({"ok": False, "error": "Missing flag"}), 400
    chal = Challenge.query.get_or_404(challenge_id)
    if not chal.is_active:
        return jsonify({"ok": False, "error": "Challenge not active"}), 400
    # Verify flag
    correct = chal.verify_flag(flag)
    # Log attempt regardless of outcome
    db.session.add(AttemptLog(user_id=current_user.id, challenge_id=chal.id, ip=_client_ip(), success=bool(correct)))
    db.session.commit()
    if not correct:
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
    def _avatar_url_for(user_id: int) -> _t.Optional[str]:
        base_dir = os.path.join(app.root_path, 'data', 'profile_images')
        for ext in ("png", "jpg", "jpeg"):
            p = os.path.join(base_dir, f"{user_id}.{ext}")
            if os.path.exists(p):
                return f"/profile_images/{user_id}"
        return None

    for u in users:
        score_val = int(u.score or 0)
        try:
            completed_val = db.session.query(Submission).filter_by(user_id=u.id).count()
        except Exception:
            completed_val = 0
        mfa_row = MfaSetting.query.filter_by(user_id=u.id, enabled=True).first()
        payload.append({
            "id": u.id,
            "username": u.username,
            "score": score_val,
            "completed": completed_val,
            "mfaEnabled": bool(mfa_row is not None),
            "avatarUrl": _avatar_url_for(u.id),
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
    teams = Team.query.order_by(asc(Team.name)).all()
    users = User.query.order_by(asc(User.username)).all()
    return render_template("admin.html", challenges=challenges, lessons=lessons, teams=teams, users=users)

# --- Profile Images: upload and serve ---
@app.post("/api/me/profile-image")
@login_required
def api_upload_profile_image():
    # Accept only PNG/JPEG, store as user_id.ext in app/data/profile_images
    file = request.files.get('image')
    if not file:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400
    content_type = (file.content_type or '').lower()
    filename = secure_filename(file.filename or '')
    ext = os.path.splitext(filename)[1].lower()
    allowed = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg'}
    if ext not in allowed or allowed[ext] != content_type:
        # Attempt to infer by content_type if extension missing/mismatch
        if content_type == 'image/png':
            ext = '.png'
        elif content_type == 'image/jpeg':
            ext = '.jpg'
        else:
            return jsonify({"ok": False, "error": "Only PNG and JPG images are allowed"}), 400
    # Basic magic header validation
    head = file.stream.read(4)
    file.stream.seek(0)
    if ext == '.png' and head != b'\x89PNG':
        return jsonify({"ok": False, "error": "Invalid PNG file"}), 400
    if ext in ('.jpg', '.jpeg') and not head.startswith(b'\xff\xd8'):
        return jsonify({"ok": False, "error": "Invalid JPG file"}), 400
    base_dir = os.path.join(app.root_path, 'data', 'profile_images')
    os.makedirs(base_dir, exist_ok=True)
    # Remove any existing image for this user with other extensions
    for e in ('.png', '.jpg', '.jpeg'):
        p = os.path.join(base_dir, f"{current_user.id}{e}")
        try:
            if os.path.exists(p): os.remove(p)
        except Exception:
            pass
    save_path = os.path.join(base_dir, f"{current_user.id}{ext}")
    try:
        file.save(save_path)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to save image: {e}"}), 500
    return jsonify({"ok": True, "avatarUrl": f"/profile_images/{current_user.id}"})

@app.get('/profile_images/<int:user_id>')
def serve_profile_image(user_id: int):
    base_dir = os.path.join(app.root_path, 'data', 'profile_images')
    for ext in ('.png', '.jpg', '.jpeg'):
        p = os.path.join(base_dir, f"{user_id}{ext}")
        if os.path.exists(p):
            # Let client cache bust via query param if needed
            return send_file(p)
    abort(404)

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
    # Persist plaintext flag for admin in separate table
    chal.secret = ChallengeSecret(flag_plain=flag)
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
        # Update or create plaintext secret
        if chal.secret:
            chal.secret.flag_plain = new_flag
        else:
            chal.secret = ChallengeSecret(flag_plain=new_flag)
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

# --- Admin: Teams CRUD ---
@app.post("/admin/teams")
@login_required
def admin_create_team():
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    if not name or not password:
        return redirect(url_for("admin_page"))
    if Team.query.filter_by(name=name).first():
        return redirect(url_for("admin_page"))
    t = Team(name=name)
    t.set_password(password)
    db.session.add(t)
    db.session.commit()
    return redirect(url_for("admin_page"))

@app.post("/admin/teams/<int:team_id>/leader")
@login_required
def admin_set_team_leader(team_id: int):
    admin_required()
    data = request.form or request.get_json(silent=True) or {}
    user_id_val = data.get("leader_user_id")
    t = Team.query.get_or_404(team_id)
    new_leader = None
    try:
        if user_id_val not in (None, "", "none"):
            new_leader = User.query.get(int(user_id_val))
    except Exception:
        new_leader = None
    t.leader_user_id = new_leader.id if new_leader else None
    # Ensure leader is a member
    if new_leader:
        mem = TeamMembership.query.filter_by(user_id=new_leader.id).first()
        if not mem:
            db.session.add(TeamMembership(team_id=t.id, user_id=new_leader.id))
        else:
            mem.team_id = t.id
    db.session.commit()
    return redirect(url_for("admin_page"))

@app.post("/admin/teams/<int:team_id>/delete")
@login_required
def admin_delete_team(team_id: int):
    admin_required()
    t = Team.query.get_or_404(team_id)
    db.session.delete(t)
    db.session.commit()
    return redirect(url_for("admin_page"))

# --- API: Teams ---
@app.get("/api/teams")
@login_required
def api_teams():
    teams = Team.query.order_by(asc(Team.name)).all()
    payload = []
    for t in teams:
        leader = User.query.get(t.leader_user_id) if t.leader_user_id else None
        member_count = TeamMembership.query.filter_by(team_id=t.id).count()
        payload.append({
            "id": t.id,
            "name": t.name,
            "leaderUsername": leader.username if leader else None,
            "memberCount": member_count,
        })
    # Mark current user's team
    my_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()
    return jsonify({
        "teams": payload,
        "myTeamId": my_membership.team_id if my_membership else None,
    })

@app.post("/api/teams/<int:team_id>/join")
@login_required
def api_join_team(team_id: int):
    data = request.get_json(silent=True) or request.form or {}
    password = (data.get("password") or "").strip()
    t = Team.query.get_or_404(team_id)
    if not password or not t.check_password(password):
        return jsonify({"ok": False, "error": "Invalid team password"}), 400
    existing = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if existing and existing.team_id == t.id:
        return jsonify({"ok": True, "joined": True, "already": True}), 200
    if existing:
        return jsonify({"ok": False, "error": "Already in a team"}), 400
    db.session.add(TeamMembership(team_id=t.id, user_id=current_user.id))
    db.session.commit()
    return jsonify({"ok": True, "joined": True, "teamId": t.id}), 200

@app.post("/api/teams")
@login_required
def api_create_team():
    data = request.get_json(silent=True) or request.form or {}
    name = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    if not name or not password:
        return jsonify({"ok": False, "error": "Missing name or password"}), 400
    if Team.query.filter_by(name=name).first():
        return jsonify({"ok": False, "error": "Team name already exists"}), 400
    existing = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if existing:
        return jsonify({"ok": False, "error": "Leave your current team first"}), 400
    t = Team(name=name, leader_user_id=current_user.id)
    t.set_password(password)
    db.session.add(t)
    db.session.flush()
    db.session.add(TeamMembership(team_id=t.id, user_id=current_user.id))
    db.session.commit()
    return jsonify({"ok": True, "created": True, "teamId": t.id}), 200
