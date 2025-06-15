from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
import os

# ───────────────────────────
# Grundkonfiguration
# ───────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")  # ✔ ENV‑Variable auf Render setzen!

DATABASE_URL = os.environ["DATABASE_URL"]  # kommt aus Render‑Postgres
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ───────────────────────────
# DB‑Schema initialisieren
# ───────────────────────────

def init_db() -> None:
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS nutzer (
                id        SERIAL PRIMARY KEY,
                username  TEXT UNIQUE NOT NULL,
                passwort  TEXT NOT NULL,
                is_admin  BOOLEAN DEFAULT FALSE
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS zeiten (
                id     SERIAL PRIMARY KEY,
                name   TEXT NOT NULL,
                zeit   TEXT NOT NULL,
                datum  DATE NOT NULL
            );
        """))

init_db()

# ───────────────────────────
# Admin‑User einmalig anlegen
# ───────────────────────────

# Nur in Produktion ausführen (Render)
if os.environ.get("FLASK_ENV") == "production":
    setup_admin()

# ───────────────────────────
# Hilfsfunktionen
# ───────────────────────────

def current_user_role():
    user = session.get("user")
    if not user:
        return None, False
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT is_admin FROM nutzer WHERE username = :u"), {"u": user}
        ).fetchone()
    return user, bool(row and row[0])

# ───────────────────────────
# Routen
# ───────────────────────────

@app.route('/')
def index():
    user, admin = current_user_role()
    with engine.begin() as conn:
        zeiten = conn.execute(
            text("SELECT name, zeit, datum FROM zeiten ORDER BY zeit ASC")
        ).all()
    return render_template("index.html", zeiten=zeiten, user=user, admin=admin)


@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')
    name = request.form['name']
    zeit = request.form['zeit']
    datum = request.form['datum']
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO zeiten (name, zeit, datum) VALUES (:n, :z, :d)"),
            {"n": name, "z": zeit, "d": datum}
        )
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT passwort FROM nutzer WHERE username = :u"),
                {"u": username}
            ).fetchone()
        if row and check_password_hash(row[0], password):
            session['user'] = username
            return redirect('/')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


# ───────────────────────────
# Admin‑bereich
# ───────────────────────────
@app.route('/admin')
def admin_panel():
    user, admin = current_user_role()
    if not admin:
        return redirect('/login')
    with engine.begin() as conn:
        users = conn.execute(text("SELECT id, username, is_admin FROM nutzer")).all()
    return render_template("admin.html", nutzer=users)


@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    _, admin = current_user_role()
    if not admin:
        return redirect('/login')
    username = request.form['username']
    password = request.form['password']
    is_admin = request.form.get('is_admin') == 'on'
    pw_hash = generate_password_hash(password)
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO nutzer (username, passwort, is_admin)
                VALUES (:u, :p, :a)
            """), {"u": username, "p": pw_hash, "a": is_admin})
    except Exception:
        return "Benutzername existiert bereits"
    return redirect('/admin')


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    _, admin = current_user_role()
    if not admin:
        return redirect('/login')
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM nutzer WHERE id = :id"), {"id": user_id})
    return redirect('/admin')


if __name__ == '__main__':
    app.run(debug=True)
