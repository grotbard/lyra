from flask import Flask, render_template, request, redirect, session
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)


def create_connection():
    return sqlite3.connect('users.db')


def setup_database():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            points INTEGER DEFAULT 0,
            admin INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()


setup_database()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return redirect('/')
    # Get the username and password from the form
    username = request.form['username']
    password = request.form['password']

    # Create a connection to the database
    conn = create_connection()
    cursor = conn.cursor()

    # Execute a query to find the user with the provided username
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()

    # Close the database connection
    conn.close()

    if user is not None and bcrypt.check_password_hash(user[2], password):
        # If the user is found and the password matches
        session['user'] = user[1]

        if user[4] == 1:  # Check if user has admin privilege (assuming admin is stored as 1)
            return redirect('/admin_dashboard')
        else:
            return redirect('/user_dashboard')
    else:
        # If user is not found or password doesn't match
        return "Invalid credentials. Please try again."


@app.route('/user_dashboard')
def user_dashboard():
    if 'user' in session:
        conn = create_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username=?', (session['user'],))
        user = cursor.fetchone()

        conn.close()

        return render_template('user.html', username=user[1], user_id=user[0], points=user[3])
    else:
        return redirect('/')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' in session:
        conn = create_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username=?', (session['user'],))
        user = cursor.fetchone()

        conn.close()

        if user[4]:  # Check if user has admin privilege
            return f"Hello, Admin! This is the admin dashboard. Points: {user[3]}"
        else:
            return "Access denied. You do not have admin privileges."
    else:
        return redirect('/')


@app.route('/admin/add_points', methods=['POST'])
def add_points():
    if 'user' in session and session['user'] == 'admin':
        user_id = request.form['user_id']
        points = int(request.form['points'])  # Make sure to convert to integer

        conn = create_connection()
        cursor = conn.cursor()

        cursor.execute('UPDATE users SET points = points + ? WHERE id = ?', (points, user_id))
        conn.commit()
        conn.close()

        return "Points updated successfully!"
    else:
        return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        repeat_password = request.form['repeat_password']

        if password == repeat_password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            conn = create_connection()
            cursor = conn.cursor()

            admin_privilege = 1 if username == 'admin' else 0

            cursor.execute('INSERT INTO users (username, password, admin) VALUES (?, ?, ?)',
                           (username, hashed_password, admin_privilege))
            conn.commit()

            conn.close()

            session['user'] = username
            return redirect('/user_dashboard')
        else:
            return "Passwords do not match. Please try again."
    return render_template('register.html')



@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
