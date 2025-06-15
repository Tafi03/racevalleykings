from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

# ──────────────────────────────────────────────────────────────
# Flask-Grundkonfiguration
# ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")   # in Render als ENV Variable setzen!

DB_PATH = "zeiten.db"

# ──────────────────────────────────────────────────────────────
# Datenbank initialisieren  (+ Spalte is_admin nachrüsten)
# ──────────────────────────────────────────────────────────────
def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        # Tabelle für Rennzeiten
        conn.execute("""
            CREATE TABLE IF NOT EXISTS zeiten (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                name    TEXT    NOT NULL,
                zeit    TEXT    NOT NULL,
                datum   TEXT    NOT NULL
            );
        """)

        # Tabelle für Nutzer  (is_admin gleich mit anlegen)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nutzer (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT UNIQUE NOT NULL,
                passwort  TEXT         NOT NULL,
                is_admin  INTEGER      DEFAULT 0
            );
        """)

        # ➜ Falls die Spalte in älteren DB-Versionen fehlt: nachrüsten
        try:
            conn.execute("ALTER TABLE nutzer ADD COLUMN is_admin INTEGER DEFAULT 0;")
        except sqlite3.OperationalError:
            pass   # Spalte existiert bereits

init_db()

# ──────────────────────────────────────────────────────────────
# Hilfsfunktionen
# ──────────────────────────────────────────────────────────────
def add_user(username: str, plaintext_password: str, is_admin: int = 0) -> None:
    """Lokale Utility-Funktion, um per Shell schnell einen Nutzer anzulegen."""
    pw_hash = generate_password_hash(plaintext_password)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO nutzer (username, passwort, is_admin) VALUES (?, ?, ?)",
            (username, pw_hash, is_admin)
        )
    print(f"User '{username}' angelegt (Admin={is_admin}).")

def current_user_role() -> tuple[str | None, bool]:
    """Liefert (username, is_admin) aus der Session/DB zurück."""
    username = session.get("user")
    if not username:
        return None, False
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT is_admin FROM nutzer WHERE username = ?", (username,)).fetchone()
    return username, bool(row and row[0] == 1)

# ──────────────────────────────────────────────────────────────
# Routen
# ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    username, is_admin = current_user_role()

    with sqlite3.connect(DB_PATH) as conn:
        zeiten = conn.execute(
            "SELECT name, zeit, datum FROM zeiten ORDER BY zeit ASC"
        ).fetchall()

    return render_template("index.html", zeiten=zeiten, user=username, admin=is_admin)


@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')

    name  = request.form['name']
    zeit  = request.form['zeit']
    datum = request.form['datum']

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO zeiten (name, zeit, datum) VALUES (?, ?, ?)",
            (name, zeit, datum)
        )
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT passwort FROM nutzer WHERE username = ?",
                (username,)
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


# ──────────────────────────────────────────────────────────────
# Admin-Bereich
# ──────────────────────────────────────────────────────────────
@app.route('/admin')
def admin_panel():
    username, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    with sqlite3.connect(DB_PATH) as conn:
        nutzer_liste = conn.execute(
            "SELECT id, username, is_admin FROM nutzer"
        ).fetchall()

    return render_template("admin.html", nutzer=nutzer_liste)


@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    admin_flag = 1 if request.form.get('is_admin') == 'on' else 0

    try:
        add_user(username, password, admin_flag)
    except sqlite3.IntegrityError:
        return "Benutzername existiert bereits"

    return redirect('/admin')


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id: int):
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM nutzer WHERE id = ?", (user_id,))
        conn.commit()
    return redirect('/admin')

if __name__ == "__main__":
    app.run(debug=True)
