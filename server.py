from flask import Flask, request, render_template
import psycopg2
import hashlib
import re

app = Flask(__name__)

# Set up a database connection
conn = psycopg2.connect(database="cyberFinal", user="postgres", password="postgres", host="localhost", port="5433")
cur = conn.cursor()


@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve the user's password hash from the database
        cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
        result = cur.fetchone()
        if not result:
            # If the username is not found in the database, return an error message to the HTML template
            error = "Invalid username or password. Please try again."
            return render_template('login.html', error=error)

        stored_password_hash = result[0]

        # Hash the input password using SHA-256
        hasher = hashlib.sha256()
        hasher.update(password.encode())
        password_hash = hasher.hexdigest()

        # Compare the password hash to the one stored in the database
        if password_hash == stored_password_hash:
            return render_template('success.html', username=username)
        else:
            error = "Invalid username or password. Please try again."
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username exists
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        if user:
            error = "Username already taken. Please choose a different username."
            return render_template('signup.html', error=error)

        # Define a regular expression for password validation
        password_regex = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^\w\d\s:])([^\s]){8,}$')
    
        # Validate password
        if not password_regex.match(password):
            error = "Password must be at least 8 characters long and include a mix of symbols, numbers, upper and lower case letters."
            return render_template('signup.html', error=error)
        
        # Hash the password using SHA-256
        hasher = hashlib.sha256()
        hasher.update(password.encode())
        password_hash = hasher.hexdigest()

        # Add user to database
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        success = 'User created successfully!'
        return render_template('signup.html', success = success)
    else:
        return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
