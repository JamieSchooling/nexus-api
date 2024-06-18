import json

from flask import Flask, request, abort
from flask_cors import CORS
import sqlite3
import base64

DB_PATH = 'nexus.db'


def register_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM users WHERE username = ?", (username,))
    data = cur.fetchone()[0]
    if data > 0:
        conn.close()
        return None

    token = base64.b64encode(f"{username}:{password}".encode('ASCII'))
    cur.execute("INSERT INTO users (token, username) VALUES(?, ?)", (token, username))
    conn.commit()
    conn.close()

    return login_user(username, password)


def login_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    token = create_token(username, password)
    cur.execute("SELECT user_id, token, username FROM users WHERE token = ?", (token,))
    data = cur.fetchone()
    conn.close()
    return data


def insert_message(author_id, content):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (author_id, content) VALUES(?, ?)", (author_id, content))
    conn.commit()
    message_id = cur.lastrowid
    conn.close()
    return message_id


def get_user_from_token(token: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, username FROM users WHERE token = ?", (token.encode('ASCII'),))
    data = cur.fetchone()
    conn.close()
    return data


def get_user_from_id(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, username FROM users WHERE user_id = ?", (user_id,))
    data = cur.fetchone()
    conn.close()
    return data


def get_messages(last_message_id, limit=50):
    if last_message_id < 0:
        last_message_id = get_last_message()[0]
        print(last_message_id)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message_id, content, author_id FROM messages WHERE message_id < ? "
                "ORDER BY message_id DESC LIMIT ?",
                (last_message_id, limit))
    data = cur.fetchall()
    data = sorted(data)
    print(data)
    conn.close()
    return data


def get_last_message():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT message_id, content, author_id FROM messages ORDER BY message_id DESC LIMIT 1")
    data = cur.fetchone()
    conn.close()
    return data


def create_token(username, password):
    return base64.b64encode(f"{username}:{password}".encode('ASCII'))


db = sqlite3.connect(DB_PATH)

cursor = db.cursor()

query = 'SELECT sqlite_version();'
cursor.execute(query)
result = cursor.fetchall()

users_table = """ CREATE TABLE IF NOT EXISTS users (
                  user_id INTEGER PRIMARY KEY,
                  token TEXT NOT NULL,
                  username TEXT NOT NULL
              ); """
cursor.execute(users_table)

messages_table = """ CREATE TABLE IF NOT EXISTS messages (
                  message_id INTEGER PRIMARY KEY,
                  content TEXT NOT NULL,
                  author_id INTEGER NOT NULL
              ); """
cursor.execute(messages_table)

db.close()

app = Flask(__name__)
CORS(app)


@app.post('/api/auth/login')
def login():
    request_data = request.json
    if 'token' in request_data:
        login_attempt = get_user_from_token(request_data['token'])
    else:
        login_attempt = login_user(request_data['username'], request_data['password'])
    if login_attempt is None:
        return {
            "message": "Incorrect username or password."
        }
    else:
        return {
            "user_id": login_attempt[0],
            "token": request_data['token'] if 'token' in request_data else login_attempt[1].decode(),
            "username": login_attempt[1 if 'token' in request_data else 2]
        }


@app.post('/api/auth/register')
def register():
    request_data = request.json
    register_attempt = register_user(request_data['username'], request_data['password'])
    if register_attempt is None:
        return {
            "message": "Username already taken."
        }
    else:
        return {
            "user_id": register_attempt[0],
            "token": register_attempt[1].decode(),
            "username": register_attempt[2]
        }


new_message_received = False


@app.route('/api/messages', methods=['GET', 'POST'])
def messages():
    if request.method == 'POST':
        token = request.headers.get('Authorization')
        author_data = get_user_from_token(token)
        if author_data is None:
            abort(code=401)
        request_data = request.json
        content = request_data['content']
        message_id = insert_message(author_data[0], content)
        author = {
            'user_id': author_data[0],
            'username': author_data[1]
        }
        return {
            'message_id': message_id,
            'content': content,
            'author': author
        }

    if request.method == 'GET':
        token = request.headers.get('Authorization')
        requester_data = get_user_from_token(token)
        if requester_data is None:
            abort(code=401)
        limit = request.args.get('limit') or '1'
        local_last_message_id = int(request.args.get('last_message_id') or "-1")
        if int(limit) == 1:
            last_message_data = get_last_message()
            while last_message_data[0] == local_last_message_id:
                last_message_data = get_last_message()
            message_id = last_message_data[0]
            content = last_message_data[1]
            author_data = get_user_from_id(last_message_data[2])
            author = {
                'user_id': author_data[0],
                'username': author_data[1]
            }
            return {
                'message_id': message_id,
                'content': content,
                'author': author
            }
        else:
            messages_data = get_messages(local_last_message_id, int(limit))
            messages_list = []
            for message_data in messages_data:
                message_id = message_data[0]
                content = message_data[1]
                author_data = get_user_from_id(message_data[2])
                author = {
                    'user_id': author_data[0],
                    'username': author_data[1]
                }
                messages_list.append({
                    'message_id': message_id,
                    'content': content,
                    'author': author
                })
            return json.dumps(messages_list)

    else:
        abort(code=400)
