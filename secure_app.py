from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "secure_secret_key"

bcrypt = Bcrypt(app)

# Create Database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

init_db()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if len(password) < 6:
            flash("Password must be at least 6 characters")
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, email, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful!")
            return redirect('/login')

        except:
            flash("Username or Email already exists!")
            return redirect('/register')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):

            session['user'] = user[1]
            flash("Login Successful!")
            return redirect('/dashboard')

        flash("Invalid Credentials!")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/login')

    return render_template(
        'dashboard.html',
        username=session['user']
    )


@app.route('/logout')
def logout():

    session.pop('user', None)
    flash("Logged Out Successfully!")
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
