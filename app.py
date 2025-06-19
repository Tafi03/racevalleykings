from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from datetime import datetime
import os

# ───── Grundkonfiguration ───────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ───── Datenbank-Schema inkl. Migration ────────────────────────────────
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
                id        SERIAL PRIMARY KEY,
                name      TEXT NOT NULL,
                zeit      TEXT NOT NULL,
                datum     DATE NOT NULL,
                "user"    TEXT,
                kategorie TEXT DEFAULT 'downhill'
            );
        """))

        # Kategorie-Spalte ergänzen, falls sie fehlt (alte DB)
        try:
            conn.execute(text("ALTER TABLE zeiten ADD COLUMN kategorie TEXT DEFAULT 'downhill';"))
        except Exception:
            pass

        # Logs: Tabelle vorhanden?
        logs_exists = conn.execute(text(
            "SELECT to_regclass('public.logs')"
        )).scalar()

        if logs_exists:
            # Prüfen, ob alte Spalte 'user' existiert → Umbenennen
            needs_rename = conn.execute(text("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='logs' AND column_name='user'
            """)).scalar()

            if needs_rename:
                try:
                    conn.execute(text('ALTER TABLE logs RENAME COLUMN "user" TO username;'))
                    print("Spalte 'user' in 'username' umbenannt.")
                except Exception as e:
                    print("Rename fehlgeschlagen:", e)
        else:
            # Tabelle neu anlegen
            conn.execute(text("""
                CREATE TABLE logs (
                    id        SERIAL PRIMARY KEY,
                    username  TEXT NOT NULL,
                    action    TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL
                );
            """))
init_db()

# ───── Hilfsfunktionen ──────────────────────────────────────────────────
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

def log_action(username: str, action: str):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO logs (username, action, timestamp)
            VALUES (:u, :a, :t)
        """), {"u": username, "a": action, "t": datetime.now()})

# ───── Routen ───────────────────────────────────────────────────────────
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

    name      = session['user']
    zeit      = request.form['zeit']
    datum     = request.form['datum']
    kategorie = request.form['kategorie']

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO zeiten (name, zeit, datum, "user", kategorie)
            VALUES (:n,:z,:d,:u,:k)
        """), {"n": name, "z": zeit, "d": datum, "u": name, "k": kategorie})

    log_action(name, f"Neue Zeit ({kategorie}) eingetragen: {zeit}")
    return redirect('/zeiten')

@app.route('/delete/<int:zid>', methods=['POST'])
def delete_time(zid):
    user, is_admin = current_user_role()
    if not user:
        return redirect('/login')

    with engine.begin() as conn:
        if is_admin:
            entry = conn.execute(text("SELECT name, zeit, kategorie FROM zeiten WHERE id = :id"), {"id": zid}).fetchone()
            conn.execute(text("DELETE FROM zeiten WHERE id = :id"), {"id": zid})
        else:
            entry = conn.execute(text("""
                SELECT name, zeit, kategorie FROM zeiten
                WHERE id = :id AND "user" = :u
            """), {"id": zid, "u": user}).fetchone()
            conn.execute(text("""
                DELETE FROM zeiten WHERE id = :id AND "user" = :u
            """), {"id": zid, "u": user})

    if entry:
        log_action(user, f"Zeit gelöscht: {entry.zeit} ({entry.kategorie}) von {entry.name}")
    return redirect('/zeiten')

# ───── Login / Logout / Registrierung ───────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        with engine.begin() as conn:
            row = conn.execute(text("SELECT passwort FROM nutzer WHERE username=:u"),
                               {"u": u}).fetchone()
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
        log_action(user, "Logout durchgeführt")
    return redirect('/login')

# ───── Admin-Panel (optional) ───────────────────────────────────────────
# @app.route('/admin')
# def admin():
#     # logs ausgeben, wenn nötig
#     pass

if __name__ == '__main__':
    app.run(debug=True)
