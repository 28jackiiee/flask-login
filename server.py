from flask import Flask, render_template, request, g, session, redirect, url_for
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('users.db')
        g.cursor = g.db.cursor()
    return g.db, g.cursor

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()


def create_tables():
    db, cursor = get_db()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        note_text TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')

    db.commit()

@app.before_first_request
def setup():
    create_tables()


@app.route('/', methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if 'register' in request.form:
            return render_template("register.html")
        if 'login' in request.form:
            return render_template("login.html")
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        username = data["username"]
        password = data["password"]
        if username == "" or password == "":
            return render_template("register.html", error_message='Please enter a correct username and password.')
        if register_user(username, password):
            session['username'] = username
            return redirect(url_for('notes'))
        else:
            return render_template("register.html", error_message='Username already exists. Please choose a different username.')
    return render_template("register.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        username = data["username"]
        password = data["password"]
        if login_user(username, password):
            session['username'] = username
            return redirect(url_for('notes'))
        else:
            return render_template("login.html", error1='Invalid username or password. Please try again.')
    return render_template("login.html")

@app.route('/notes', methods=["GET", "POST"])
def notes():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        data = request.form
        note_text = data["note_text"]
        user_id = get_user_id(session['username'])
        add_note(user_id, note_text)
        return redirect(url_for('notes'))
    else:
        user_id = get_user_id(session['username'])
        user_notes = get_user_notes(user_id)
        return render_template("notes.html", user_notes=user_notes)

@app.route('/logout')
def logout():
    session.clear()
    return render_template("index.html")

@app.route('/delete-note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    db, cursor = get_db()

    cursor.execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, get_user_id(session['username'])))
    note = cursor.fetchone()
    if note is None:
        return "Note not found or unauthorized."


    cursor.execute("DELETE FROM notes WHERE id=?", (note_id,))
    db.commit()

    return redirect(url_for('notes'))


def register_user(username, password):
    db, cursor = get_db()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    if cursor.fetchone() is None:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password.decode('utf-8')))
        db.commit()
        return True
    return False

def login_user(username, password):
    db, cursor = get_db()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if result is not None:
        stored_hashed_password_str = result[0]

        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password_str.encode('utf-8')):
            return True

    return False

def get_user_id(username):
    db, cursor = get_db()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    if result is not None:
        return result[0]
    return None

def add_note(user_id, note_text):
    db, cursor = get_db()
    cursor.execute("INSERT INTO notes (user_id, note_text) VALUES (?, ?)", (user_id, note_text))
    db.commit()

def get_user_notes(user_id):
    db, cursor = get_db()
    cursor.execute("SELECT * FROM notes WHERE user_id=?", (user_id,))
    return cursor.fetchall()


if __name__ == "__main__":
    app.run(debug=True)
