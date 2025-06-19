from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from datetime import datetime
import os

# ─────────────────── Grundkonfiguration ────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ─────────────────── Datenbank & Migration ─────────────────────────────
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

        # Kategorie-Spalte nachrüsten
        try:
            conn.execute(text("ALTER TABLE zeiten ADD COLUMN kategorie TEXT DEFAULT 'downhill';"))
        except Exception:
            pass

    # Logs separat prüfen, damit Fehler hier keine Transaktion killen
    try:
        with engine.begin() as conn:
            exists = conn.execute(text("SELECT to_regclass('public.logs')")).scalar()

            if exists is None:
                conn.execute(text("""
                    CREATE TABLE logs (
                        id        SERIAL PRIMARY KEY,
                        username  TEXT NOT NULL,
                        action    TEXT NOT NULL,
                        timestamp TIMESTAMP NOT NULL
                    );
                """))
            else:
                needs_rename = conn.execute(text("""
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='logs' AND column_name='user'
                """)).scalar()
                if needs_rename:
                    conn.execute(text('ALTER TABLE logs RENAME COLUMN "user" TO username;'))
    except Exception as e:
        print("[WARN] Log-Migration:", e)

init_db()

# ─────────────────── Hilfsfunktionen ───────────────────────────────────
def current_user_role():
    username = session.get("user")
    if not username:
        return None, False
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT is_admin FROM nutzer WHERE username=:u"
        ), {"u": username}).fetchone()
    return username, bool(row and row[0])

def log_action(username: str, action: str):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO logs (username, action, timestamp)
            VALUES (:u, :a, :t)
        """), {"u": username, "a": action, "t": datetime.now()})

def add_user(username: str, password_plain: str, is_admin: bool = False):
    pw_hash = generate_password_hash(password_plain)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO nutzer (username, passwort, is_admin)
            VALUES (:u, :p, :a)
            ON CONFLICT (username) DO NOTHING
        """), {"u": username, "p": pw_hash, "a": is_admin})

# ─────────────────── Öffentliche Routen ────────────────────────────────
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
            FROM zeiten
            WHERE kategorie='downhill'
            ORDER BY zeit ASC
        """)).all()
        uphill = conn.execute(text("""
            SELECT id,name,zeit,datum,"user"
            FROM zeiten
            WHERE kategorie='uphill'
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

    username = session['user']
    zeit  = request.form['zeit']
    datum = request.form['datum']
    kat   = request.form['kategorie']

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO zeiten (name, zeit, datum, "user", kategorie)
            VALUES (:n,:z,:d,:u,:k)
        """), {"n": username, "z": zeit, "d": datum, "u": username, "k": kat})

    log_action(username, f"Zeit hinzugefügt ({kat}): {zeit} am {datum}")
    return redirect('/zeiten')

@app.route('/delete/<int:zid>', methods=['POST'])
def delete_time(zid):
    username, is_admin = current_user_role()
    if not username:
        return redirect('/login')

    with engine.begin() as conn:
        if is_admin:
            conn.execute(text("DELETE FROM zeiten WHERE id=:id"), {"id": zid})
        else:
            conn.execute(text("""
                DELETE FROM zeiten WHERE id=:id AND "user"=:u
            """), {"id": zid, "u": username})

    log_action(username, f"Zeit gelöscht (ID {zid})")
    return redirect('/zeiten')

# ─────────────────── Auth ───────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        with engine.begin() as conn:
            row = conn.execute(text(
                "SELECT passwort FROM nutzer WHERE username=:u"
            ), {"u": u}).fetchone()
        if row and check_password_hash(row[0], p):
            session['user'] = u
            log_action(u, "Login")
            return redirect('/zeiten')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    u = session.pop('user', None)
    if u:
        log_action(u, "Logout")
    return redirect('/login')

# ─────────────────── Admin-Panel: Benutzerverwaltung ────────────────────
@app.route('/admin')
def admin_panel():
    user, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    with engine.begin() as conn:
        nutzer = conn.execute(text("""
            SELECT id, username, is_admin
            FROM nutzer
            ORDER BY id
        """)).all()

    return render_template('admin.html', nutzer=nutzer, user=user)

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    user, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    new_user   = request.form['username']
    password   = request.form['password']
    admin_flag = request.form.get('is_admin') == 'on'

    add_user(new_user, password, admin_flag)
    log_action(user, f"Benutzer angelegt: {new_user} (Admin={admin_flag})")
    return redirect('/admin')

@app.route('/admin/delete-user/<int:uid>', methods=['POST'])
def admin_delete_user(uid):
    user, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM nutzer WHERE id=:i"), {"i": uid})
    log_action(user, f"Benutzer gelöscht (ID {uid})")
    return redirect('/admin')

# ─────────────────── Admin-Logs ─────────────────────────────────────────
@app.route('/admin/logs')
def admin_logs():
    user, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    with engine.begin() as conn:
        logs = conn.execute(text("""
            SELECT username, action, timestamp
            FROM logs ORDER BY timestamp DESC
            LIMIT 500
        """)).all()

    return render_template('logs.html', logs=logs, user=user)

# ─────────────────── App-Start (lokal) ─────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)
