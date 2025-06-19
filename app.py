from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from datetime import datetime
import os

# ─────────── Grundkonfiguration ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ─────────── DB-Schema & Migrationen ────────────────────────────────────
def init_db() -> None:
    with engine.begin() as conn:
        # Nutzer
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS nutzer (
                id        SERIAL PRIMARY KEY,
                username  TEXT UNIQUE NOT NULL,
                passwort  TEXT NOT NULL,
                is_admin  BOOLEAN DEFAULT FALSE
            );
        """))
        # Zeiten
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS zeiten (
                id     SERIAL PRIMARY KEY,
                name   TEXT NOT NULL,
                zeit   TEXT NOT NULL,
                datum  DATE NOT NULL,
                "user" TEXT,
                kategorie TEXT DEFAULT 'downhill'
            );
        """))
        # Logs
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS logs (
                id        SERIAL PRIMARY KEY,
                username      TEXT NOT NULL,
                action    TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL
            );
        """))
        # ggf. kategorie nachrüsten
        try:
            conn.execute(text("ALTER TABLE zeiten ADD COLUMN kategorie TEXT DEFAULT 'downhill';"))
        except Exception:
            pass
init_db()

# ─────────── Hilfsfunktionen ────────────────────────────────────────────
def current_user_role():
    user = session.get("user")
    if not user:
        return None, False
    with engine.begin() as conn:
        row = conn.execute(text("SELECT is_admin FROM nutzer WHERE username=:u"), {"u": user}).fetchone()
    return user, bool(row and row[0])

def log_action(user: str, action: str) -> None:
    """Schreibt einen Eintrag in die Log-Tabelle."""
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO logs (username, action, timestamp)
            VALUES (:u, :a, :t)
        """), {"u": user, "a": action, "t": datetime.now()})

# ─────────── Routen ─────────────────────────────────────────────────────
@app.route('/')
def root():
    return redirect('/zeiten')

@app.route('/zeiten')
def zeiten():
    if 'user' not in session:
        return redirect('/login')

    user, admin = current_user_role()
    with engine.begin() as conn:
        downhill = conn.execute(text("""
            SELECT id,name,zeit,datum,"user"
            FROM zeiten WHERE kategorie='downhill'
            ORDER BY zeit ASC
        """)).all()
        uphill = conn.execute(text("""
            SELECT id,name,zeit,datum,"user"
            FROM zeiten WHERE kategorie='uphill'
            ORDER BY zeit ASC
        """)).all()

    return render_template(
        "index.html",
        downhill=downhill,
        uphill=uphill,
        user=user,
        admin=admin
    )

@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')

    name  = session['user']
    zeit  = request.form['zeit']
    datum = request.form['datum']
    kat   = request.form['kategorie']  # downhill / uphill

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO zeiten (name, zeit, datum, "user", kategorie)
            VALUES (:n,:z,:d,:u,:k)
        """), {"n": name, "z": zeit, "d": datum, "u": name, "k": kat})

    log_action(name, f"Zeit hinzugefügt ({kat}): {zeit} am {datum}")
    return redirect('/zeiten')

@app.route('/delete/<int:zid>', methods=['POST'])
def delete_time(zid):
    user, is_admin = current_user_role()
    if not user:
        return redirect('/login')

    sql = ("DELETE FROM zeiten WHERE id=:id"
           if is_admin else
           'DELETE FROM zeiten WHERE id=:id AND "user"=:u')

    with engine.begin() as conn:
        conn.execute(text(sql), {"id": zid, "u": user})

    log_action(user, f"Zeit gelöscht (ID {zid})")
    return redirect('/zeiten')

# ─────────── Login / Logout ────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        with engine.begin() as conn:
            row = conn.execute(text("SELECT passwort FROM nutzer WHERE username=:u"), {"u": u}).fetchone()
        if row and check_password_hash(row[0], p):
            session['user'] = u
            log_action(u, "Login erfolgreich")
            return redirect('/zeiten')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    user = session.pop('user', None)
    if user:
        log_action(user, "Logout")
    return redirect('/login')

# ─────────── Admin-Log-Ansicht ──────────────────────────────────────────
@app.route('/admin/logs')
def admin_logs():
    user, admin = current_user_role()
    if not admin:
        return redirect('/login')
    with engine.begin() as conn:
        logs = conn.execute(text("""
            SELECT user, action, timestamp
            FROM logs ORDER BY timestamp DESC
            LIMIT 500
        """)).all()
    return render_template("logs.html", logs=logs, user=user, admin=True)

# ─────────── Admin-Panel (gekürzt, bleibt wie gehabt) ───────────────────
# ...

if __name__ == '__main__':
    app.run(debug=True)
