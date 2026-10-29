"""Application Security Demo: login, hashing, validation, sessions, RBAC and security headers.

Run:  python app.py   then open http://127.0.0.1:5000
"""
import functools
import os
import re
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("NOTE: SECRET_KEY not set; using a temporary random key (sessions reset on restart).")
app.config.update(
    SECRET_KEY=_secret,
    DATABASE=os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "demo.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
    MAX_CONTENT_LENGTH=16 * 1024,
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
ROLES = ("user", "admin")


# ------------------------------------------------------------ database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_e):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')))""")
        if not db.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
            pw = os.environ.get("DEMO_ADMIN_PASSWORD")
            generated = pw is None
            pw = pw or secrets.token_urlsafe(12)
            db.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')",
                       (generate_password_hash(pw),))
            if generated:  # shown once in the console so no password is ever hard-coded
                print(f"\n*** First run: admin account created. Username: admin  Password: {pw}\n"
                      "*** Save it now; it is not stored in plain text anywhere.\n")


# ------------------------------------------------------------ security helpers
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf_token", ""), session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token.")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def role_required(role):
    """Role-based access control: role is re-read from the DB on every request."""
    def deco(view):
        @functools.wraps(view)
        @login_required
        def wrapped(*a, **kw):
            row = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not row or row["role"] != role:
                abort(403)
            return view(*a, **kw)
        return wrapped
    return deco


def check_password_rules(pw):
    errs = []
    if not 10 <= len(pw) <= 128:
        errs.append("Password must be 10-128 characters long.")
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        errs.append("Password needs at least one letter and one number.")
    return errs


# ------------------------------------------------------------ routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        errs = [] if USERNAME_RE.match(u) else ["Username must be 3-30 letters, numbers or underscores."]
        errs += check_password_rules(p)
        if not errs:
            try:  # parameterised query -> no SQL injection; new users are ALWAYS role 'user'
                get_db().execute("INSERT INTO users (username, password_hash, role) VALUES (?,?, 'user')",
                                 (u, generate_password_hash(p)))
                get_db().commit()
                flash("Registered. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errs.append("That username is already taken.")
        for e in errs:
            flash(e, "error")
        return render_template("register.html", username=u), 400
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], p):
            session.clear()
            session.permanent = True
            session.update(user_id=row["id"], username=row["username"])
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=u), 401
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    role = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()["role"]
    return render_template("dashboard.html", role=role)


@app.route("/admin")
@role_required("admin")
def admin():
    users = get_db().execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/role/<int:user_id>", methods=["POST"])
@role_required("admin")
def change_role(user_id):
    new_role = request.form.get("role", "")
    if new_role not in ROLES:
        abort(400, "Unknown role.")
    if user_id == session["user_id"]:
        flash("You cannot change your own role.", "error")
    else:
        get_db().execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
        get_db().commit()
        flash("Role updated.", "success")
    return redirect(url_for("admin"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.errorhandler(400)
def e400(e):
    return render_template("error.html", code=400, message=e.description), 400


@app.errorhandler(403)
def e403(_e):
    return render_template("error.html", code=403, message="Forbidden: you do not have permission to view this page."), 403


@app.errorhandler(404)
def e404(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def e413(_e):
    return render_template("error.html", code=413, message="Request too large."), 413


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
