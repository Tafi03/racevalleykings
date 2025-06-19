from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
import os

# ───── Grundkonfiguration ───────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ───── Datenbank-Schema & Migration (kategorie-Spalte) ──────────────────
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
        # Falls kategorie-Spalte in älteren DBs fehlt
        try:
            conn.execute(text("ALTER TABLE zeiten ADD COLUMN kategorie TEXT DEFAULT 'downhill';"))
        except Exception:
            pass
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

    name      = session['user']               # Login-Name automatisch
    zeit      = request.form['zeit']
    datum     = request.form['datum']
    kategorie = request.form['kategorie']     # downhill / uphill

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO zeiten (name, zeit, datum, "user", kategorie)
            VALUES (:n,:z,:d,:u,:k)
        """), {"n": name, "z": zeit, "d": datum, "u": name, "k": kategorie})
    return redirect('/zeiten')

@app.route('/delete/<int:zid>', methods=['POST'])
def delete_time(zid):
    user, is_admin = current_user_role()
    if not user:
        return redirect('/login')

    sql = ("DELETE FROM zeiten WHERE id = :id"
           if is_admin else
           'DELETE FROM zeiten WHERE id = :id AND "user" = :u')

    with engine.begin() as conn:
        conn.execute(text(sql), {"id": zid, "u": user})
    return redirect('/zeiten')

# ───── Login / Logout / Registrierung (optional) ────────────────────────
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
            return redirect('/zeiten')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ───── Admin-Panel unverändert (hier ausgelassen, bleibt wie gehabt) ────
# ...

if __name__ == '__main__':
    app.run(debug=True)
