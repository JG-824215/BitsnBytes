from http.server import HTTPServer, SimpleHTTPRequestHandler
import cgi
import hashlib
import json
import sqlite3
from time import time
import secrets
import http.cookies

# Define the port as a variable
HOST = "0.0.0.0"
PORT = 8000

class Block:
    def __init__(self, index, timestamp, vote, username):
        self.index = index
        self.timestamp = timestamp
        self.vote = vote
        self.username = username
        self.previous_hash = ''
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.vote}{self.username}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class CustomHandler(SimpleHTTPRequestHandler):
    # The varible tracks the release status, the result is hidden before the admin click "Release Result"
    result_released = False 
    db_connection = sqlite3.connect('blockchain_database.db')
    db_cursor = db_connection.cursor()

    # Initial setup for database tables and blockchain
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS blockchain (
            block_index INTEGER PRIMARY KEY,
            timestamp TEXT,
            vote TEXT,
            previous_hash TEXT,
            hash TEXT,
            username TEXT
        )
    ''')
    db_connection.commit()

    # Load blockchain from database
    blockchain = []
    db_cursor.execute('SELECT * FROM blockchain ORDER BY block_index')
    rows = db_cursor.fetchall()
    for row in rows:
        block = Block(row[0], row[1], row[2], row[5])
        block.previous_hash = row[3]
        block.hash = row[4]
        blockchain.append(block)

    # Initialize votes dictionary
    votes = {'yes': 0, 'no': 0}
    for block in blockchain:
        if block.vote in votes:
            votes[block.vote] += 1

    def save_user_to_database(self, username, hashed_password):
        CustomHandler.db_cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        CustomHandler.db_connection.commit()

    @staticmethod
    def check_user_credentials(username, hashed_password):
        CustomHandler.db_cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
        return CustomHandler.db_cursor.fetchone() is not None


    def do_GET(self):
        if self.path in ['/', '/registration']:
            self.path = '/registration.html'
        elif self.path.startswith('/dashboard'):
            # Check for the presence of the session cookie
            if 'Cookie' in self.headers:
                cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
                if 'session' in cookies:
                    username = cookies['session'].value
                    print(f"Currently logged in as: {username}")
                
                    # Read and personalize the dashboard HTML file
                    with open('dashboard.html', 'r') as file:
                        html_content = file.read()
                        
                    # This specified what happened if the logged in user is "administrator"    
                    if username == 'administrator':
                        # Add a button for releasing results (only for administrator)
                        release_button_html = "<button onclick=\"window.location.href='/release_results'\">Release Voting Result</button>"
                        html_content = html_content.replace("<!-- Admin Button Placeholder -->", release_button_html)
                    
                    # Hello {username}. Welcome to userdash
                    personalized_content = html_content.replace("{username}", username)

                    # Send the personalized content as a response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(personalized_content.encode())
                    return
                                
                else:
                    # Redirect to login if session cookie is missing
                    self.send_response(303)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return

            self.path = '/dashboard.html'
        elif self.path == '/Result.html':
                if CustomHandler.result_released:
                    try:
                        with open('Result.html', 'r') as file:
                            html_content = file.read()

                        results_content = f"<p>Yes: {self.votes['yes']}</p><p>No: {self.votes['no']}</p>"
                        html_content = html_content.replace("<!-- Voting results will be dynamically inserted here by the server -->", results_content)

                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(html_content.encode())
                    except FileNotFoundError:
                        self.send_error(404, "File not found")
                else:
                    # Redirect users to ResultNotAvailable page
                    self.send_response(303)  # HTTP status code for "See Other"
                    self.send_header('Location', '/ResultNotAvailable.html')
                    self.end_headers()
            
        elif self.path == '/ResultNotAvailable.html':
            try:
                with open('ResultNotAvailable.html', 'r') as file:
                    html_content = file.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_content.encode())
            except FileNotFoundError:
                self.send_error(404, "File not found")
        
        elif self.path == '/thankyou':
            self.path = '/TyForVoting.html'
        
        elif self.path == '/logout_confirm':
            self.path = '/logout_confirm.html'
        
        elif self.path == '/confirm_logout':
            # Clear the session cookie
            self.send_response(303)
            self.send_header('Location', '/Home.html')
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()
        
        elif self.path == '/Home.html':
            username = ''
            if 'Cookie' in self.headers:
                cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
                if 'session' in cookies:
                    username = cookies['session'].value

            with open('Home.html', 'r') as file:
                html_content = file.read()

            if username:
                user_section = f"<a class='u-button-style u-nav-link u-text-active-palette-1-base u-text-hover-palette-2-base' href='/logout' style='padding: 22px 24px;'>{username} | Logout</a>"
            else:
                user_section = "<a class='u-button-style u-nav-link u-text-active-palette-1-base u-text-hover-palette-2-base' href='Login.html' style='padding: 22px 24px;'>Login</a>"

            html_content = html_content.replace("{user_section}", user_section)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_content.encode())

        # specify what happened if the admin click release button
        elif  self.path == '/release_results':
            CustomHandler.result_released = True
            # Redirect back to the dashboard
            self.send_response(303)
            self.send_header('Location', '/dashboard')
            self.end_headers()

        return super().do_GET()

    def do_POST(self):
        if self.path == '/submit':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type'],
                         })

            firstname = form.getvalue('firstname')
            lastname = form.getvalue('lastname')
            username = form.getvalue('username')
            password = form.getvalue('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            try:
                self.save_user_to_database(username, hashed_password)
                # Start session and redirect to dashboard
                self.send_response(303)
                self.send_header('Location', '/dashboard')
                self.send_header('Set-Cookie', f'session={username}; Path=/')
                self.end_headers()
            except sqlite3.IntegrityError:
                # Handle the error (e.g., username already exists)
                self.send_response(400)  # Bad Request
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Username already exists. Please try a different username.")

            # Start session and redirect to dashboard
            self.send_response(303)
            self.send_header('Location', '/dashboard')
            self.send_header('Set-Cookie', f'session={username}; Path=/')
            self.end_headers()

        elif self.path == '/login':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type'],
                         })

            username = form.getvalue('username')
            password = form.getvalue('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            if CustomHandler.check_user_credentials(username, hashed_password):
                # Set a session cookie
                self.send_response(303)
                self.send_header('Location', '/dashboard')
                self.send_header('Set-Cookie', f'session={username}; Path=/')
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Invalid username or password")

        elif self.path == '/logout':
            # Clear the session cookie
            self.send_response(303)
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()

        elif self.path == '/home_logout':
            self.send_response(303)
            self.send_header('Location', '/Home.html')
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()


        elif self.path == '/vote':
                cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
                username = cookies['session'].value if 'session' in cookies else None

                if username is None:
                    self.send_response(401)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Please log in to vote.")
                    return

                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
                )

                vote = form.getvalue('vote')

                # Check blockchain for existing vote by user
                for block in CustomHandler.blockchain:
                    if block.username == username:
                        self.send_response(400)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(b"You have already voted.")
                        return

                # Record new vote in blockchain
                new_index = len(CustomHandler.blockchain)
                new_timestamp = time()
                new_block = Block(new_index, new_timestamp, vote, username)
                if CustomHandler.blockchain:
                    new_block.previous_hash = CustomHandler.blockchain[-1].hash
                new_block.hash = new_block.calculate_hash()
                CustomHandler.blockchain.append(new_block)

                # Save new block to database
                CustomHandler.db_cursor.execute('INSERT INTO blockchain (block_index, timestamp, vote, previous_hash, hash, username) VALUES (?, ?, ?, ?, ?, ?)', 
                                                (new_block.index, new_block.timestamp, new_block.vote, new_block.previous_hash, new_block.hash, username))
                CustomHandler.db_connection.commit()

                CustomHandler.votes[vote] += 1

                self.send_response(303)
                self.send_header('Location', '/thankyou')
                self.end_headers()

 # Start the server
httpd = HTTPServer((HOST, PORT), CustomHandler)
print(f"Serving at port {PORT}")
httpd.serve_forever()