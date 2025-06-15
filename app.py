from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
import os

# ——— Konfiguration ———
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL, future=True)

# ——— Admin-Setup (nur beim allerersten Start, dann löschen!) ———
@app.before_first_request
def setup_admin():
    with engine.begin() as conn:
        result = conn.execute(
            text("SELECT COUNT(*) FROM nutzer WHERE username = :u"),
            {"u": "admin"}
        ).scalar()

        if result == 0:
            conn.execute(text("""
                INSERT INTO nutzer (username, passwort, is_admin)
                VALUES (:u, :p, 1)
            """), {
                "u": "admin",
                "p": generate_password_hash("beEnte21")
            })

# ——— Hilfsfunktionen ———
def current_user_role():
    username = session.get("user")
    if not username:
        return None, False
    with engine.begin() as conn:
        result = conn.execute(text(
            "SELECT is_admin FROM nutzer WHERE username = :u"
        ), {"u": username}).fetchone()
    return username, bool(result and result[0] == 1)

# ——— Routen ———
@app.route('/')
def index():
    username, is_admin = current_user_role()
    with engine.begin() as conn:
        zeiten = conn.execute(text(
            "SELECT name, zeit, datum FROM zeiten ORDER BY zeit ASC"
        )).fetchall()
    return render_template("index.html", zeiten=zeiten, user=username, admin=is_admin)


@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')
    name = request.form['name']
    zeit = request.form['zeit']
    datum = request.form['datum']
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO zeiten (name, zeit, datum) VALUES (:n, :z, :d)"
        ), {"n": name, "z": zeit, "d": datum})
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with engine.begin() as conn:
            row = conn.execute(text(
                "SELECT passwort FROM nutzer WHERE username = :u"
            ), {"u": username}).fetchone()

        if row and check_password_hash(row[0], password):
            session['user'] = username
            return redirect('/')
        error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


@app.route('/admin')
def admin_panel():
    username, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')
    with engine.begin() as conn:
        nutzer_liste = conn.execute(text(
            "SELECT id, username, is_admin FROM nutzer"
        )).fetchall()
    return render_template("admin.html", nutzer=nutzer_liste)


@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    admin_flag = 1 if request.form.get('is_admin') == 'on' else 0
    pw_hash = generate_password_hash(password)

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO nutzer (username, passwort, is_admin)
                VALUES (:u, :p, :a)
            """), {"u": username, "p": pw_hash, "a": admin_flag})
    except Exception:
        return "Benutzername existiert bereits"

    return redirect('/admin')


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    _, is_admin = current_user_role()
    if not is_admin:
        return redirect('/login')
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM nutzer WHERE id = :id"), {"id": user_id})
    return redirect('/admin')


if __name__ == "__main__":
    app.run(debug=True)
