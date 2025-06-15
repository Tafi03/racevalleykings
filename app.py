from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
import os

# ── Flask-Grundkonfiguration ──────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")      # in Render setzen!

DATABASE_URL = os.environ["DATABASE_URL"]                        # Render-Postgres
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ── Datenbank-Schema einmalig anlegen ────────────────────────────────
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

# ── Hilfsfunktionen ─────────────────────────────────────────────────
def current_user_role():
    user = session.get("user")
    if not user:
        return None, False
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT is_admin FROM nutzer WHERE username = :u"),
            {"u": user}
        ).fetchone()
    return user, bool(row and row[0])

def add_user(username: str, password_plain: str, is_admin: bool = False):
    pw_hash = generate_password_hash(password_plain)
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO nutzer (username, passwort, is_admin)
                VALUES (:u, :p, :a)
                ON CONFLICT (username) DO NOTHING
            """),
            {"u": username, "p": pw_hash, "a": is_admin}
        )

# ── Routen ──────────────────────────────────────────────────────────
@app.route('/')
def root():
    """Start: immer erst zur Login-Seite – außer man ist eingeloggt."""
    if 'user' in session:
        return redirect('/zeiten')
    return redirect('/login')

@app.route('/zeiten')
def zeiten():
    """Hauptseite (Rangliste) – nur für eingeloggte User."""
    if 'user' not in session:
        return redirect('/login')

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
    name  = request.form['name']
    zeit  = request.form['zeit']
    datum = request.form['datum']
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO zeiten (name, zeit, datum) VALUES (:n, :z, :d)"),
            {"n": name, "z": zeit, "d": datum}
        )
    return redirect('/zeiten')

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
            return redirect('/zeiten')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ── Admin-Bereich ────────────────────────────────────────────────────
@app.route('/admin')
def admin_panel():
    user, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')
    with engine.begin() as conn:
        nutzer = conn.execute(
            text("SELECT id, username, is_admin FROM nutzer")
        ).all()
    return render_template("admin.html", nutzer=nutzer, user=user, admin=True)

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    username   = request.form['username']
    password   = request.form['password']
    admin_flag = request.form.get('is_admin') == 'on'
    add_user(username, password, admin_flag)
    return redirect('/admin')

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM nutzer WHERE id = :id"), {"id": user_id})
    return redirect('/admin')

# ── Lokalstart ──────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)
