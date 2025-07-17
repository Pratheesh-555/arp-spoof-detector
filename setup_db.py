import sqlite3
import bcrypt

# Connect to the database (or create it if it doesn't exist)
conn = sqlite3.connect('users.db')

# Create a cursor object
cursor = conn.cursor()

# Create the users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')

# Add a sample user (with hashed password)
username = "admin"
password = "password"

# Hash the password before storing it
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Insert the user
cursor.execute('''
INSERT OR IGNORE INTO users (username, password) 
VALUES (?, ?)
''', (username, hashed_password))

# Commit and close the connection
conn.commit()
conn.close()

print("Database setup complete.")
