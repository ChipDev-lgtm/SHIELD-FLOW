import sqlite3
import hashlib
import socket
import threading

DB_NAME = "userdata.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS userdata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Make sure DB & table exist
init_db()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen()

def handle_connection(c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode().strip()

    c.send("Password: ".encode())
    password = c.recv(1024).decode().strip()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username, hashed_password))
    result = cur.fetchone()

    if result:
        c.send("Login successful!\n".encode())
    else:
        c.send("Login failed.\n".encode())

    conn.close()
    c.close()

while True:
    client, addr = server.accept()
    threading.Thread(target=handle_connection, args=(client,)).start()
