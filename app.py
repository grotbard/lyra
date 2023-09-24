from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random string

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Implement your authentication logic here (e.g., check against a database)
        # For simplicity, I'll use a hardcoded check
        if username == 'admin' and password == 'admin':
            session['user'] = 'admin'
            return redirect('/admin')
        elif username == 'user' and password == 'user':
            session['user'] = 'user'
            return redirect('/user')
        else:
            return "Invalid credentials. Please try again."

    return render_template('login.html')

@app.route('/user')
def user():
    if 'user' in session and session['user'] == 'user':
        return render_template('user.html', username='User', points=10)  # Example points value
    else:
        return redirect('/')

@app.route('/admin')
def admin():
    if 'user' in session and session['user'] == 'admin':
        return render_template('admin.html')
    else:
        return redirect('/')

@app.route('/admin/add_points', methods=['POST'])
def add_points():
    if 'user' in session and session['user'] == 'admin':
        user_id = request.form['user_id']
        points = request.form['points']
        # Implement logic to update points for the user in the database
        return "Points updated successfully!"
    else:
        return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
