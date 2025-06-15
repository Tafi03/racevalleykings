from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super-geheim'  # Ändere das in etwas Sicheres

# Feste Benutzerliste (du kannst beliebig viele eintragen)
users = {
    "dominik": generate_password_hash("meinpasswort"),
    "lisa": generate_password_hash("rennfahrer123")
}

def init_db():
    with sqlite3.connect("zeiten.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS zeiten (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                zeit TEXT NOT NULL,
                datum TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nutzer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                passwort TEXT NOT NULL
            );
        """)
init_db()

@app.route('/')
def index():
    # 1) User-Info aus der Session
    username = session.get("user")
    is_admin = False

    # 2) Wenn eingeloggt → in DB nachsehen, ob Admin
    if username:
        with sqlite3.connect("zeiten.db") as conn:
            row = conn.execute(
                "SELECT is_admin FROM nutzer WHERE username = ?",
                (username,)
            ).fetchone()
            is_admin = (row and row[0] == 1)

    # 3) Rennzeiten laden
    with sqlite3.connect("zeiten.db") as conn:
        zeiten = conn.execute(
            "SELECT name, zeit, datum FROM zeiten ORDER BY zeit ASC"
        ).fetchall()

    # 4) Dem Template alles mitgeben
    return render_template(
        "index.html",
        zeiten=zeiten,
        user=username,
        admin=is_admin
    )

@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')
    name = request.form['name']
    zeit = request.form['zeit']
    datum = request.form['datum']
    with sqlite3.connect("zeiten.db") as conn:
        conn.execute("INSERT INTO zeiten (name, zeit, datum) VALUES (?, ?, ?)", (name, zeit, datum))
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect("zeiten.db") as conn:
            result = conn.execute("SELECT passwort FROM nutzer WHERE username = ?", (username,)).fetchone()
        if result and check_password_hash(result[0], password):
            session['user'] = username
            return redirect('/')
        else:
            error = "Login fehlgeschlagen"
    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

def add_user(username, plaintext_password):
    from werkzeug.security import generate_password_hash
    pw_hash = generate_password_hash(plaintext_password)
    with sqlite3.connect("zeiten.db") as conn:
        conn.execute("INSERT INTO nutzer (username, passwort) VALUES (?, ?)", (username, pw_hash))
    print(f"Nutzer '{username}' hinzugefügt.")

@app.route('/admin')
def admin_panel():
    if 'user' not in session:
        return redirect('/login')

    with sqlite3.connect("zeiten.db") as conn:
        # Prüfen, ob der aktuelle Benutzer ein Admin ist
        user = session['user']
        result = conn.execute("SELECT is_admin FROM nutzer WHERE username = ?", (user,)).fetchone()
        if not result or result[0] != 1:
            return "Zugriff verweigert", 403

        nutzer_liste = conn.execute("SELECT id, username, is_admin FROM nutzer").fetchall()

    return render_template("admin.html", nutzer=nutzer_liste)

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    if 'user' not in session:
        return redirect('/login')

    with sqlite3.connect("zeiten.db") as conn:
        user = session['user']
        result = conn.execute("SELECT is_admin FROM nutzer WHERE username = ?", (user,)).fetchone()
        if not result or result[0] != 1:
            return "Zugriff verweigert", 403

        username = request.form['username']
        password = request.form['password']
        is_admin = 1 if request.form.get('is_admin') == 'on' else 0
        pw_hash = generate_password_hash(password)

        try:
            conn.execute("INSERT INTO nutzer (username, passwort, is_admin) VALUES (?, ?, ?)", (username, pw_hash, is_admin))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Benutzername existiert bereits"
    return redirect('/admin')

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user' not in session:
        return redirect('/login')

    with sqlite3.connect("zeiten.db") as conn:
        user = session['user']
        result = conn.execute("SELECT is_admin FROM nutzer WHERE username = ?", (user,)).fetchone()
        if not result or result[0] != 1:
            return "Zugriff verweigert", 403

        conn.execute("DELETE FROM nutzer WHERE id = ?", (user_id,))
        conn.commit()
    return redirect('/admin')