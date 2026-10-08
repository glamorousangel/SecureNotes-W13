"""
SecureNotes API — Week 13 Security Lab
Secure version of the FastAPI notes service.
"""

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# Keep the signing secret outside the source code. For the lab, a random
# fallback keeps the app runnable if the environment variable is not set.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Return a salted PBKDF2 password hash."""
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(derived).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password without exposing whether the hash matches early."""
    try:
        salt_b64, hash_b64 = stored.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(hash_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def make_token(user_id: int) -> str:
    """Create a signed token containing a user id and expiration time."""
    expires = int(time.time()) + 3600
    payload = f"{user_id}:{expires}".encode()
    signature = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(payload).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    )


def current_user(authorization: str = Header(default=None)):
    """Validate the bearer token and return the authenticated user."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(encoded_payload + "=")
        signature = base64.urlsafe_b64decode(encoded_signature + "=")
        expected = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError

        user_id_text, expires_text = payload.decode().split(":", 1)
        user_id = int(user_id_text)
        if int(time.time()) >= int(expires_text):
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return row


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # Seed accounts. Passwords are stored as salted hashes, not plaintext.
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("admin", hash_password("admin123"), 1))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("alice", hash_password("alicepass"), 0))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("bob", hash_password("bobpass"), 0))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (2, "Alice diary", "Alice secret note"))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (3, "Bob plans", "Bob secret note"))
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    # Do not expose exception details or stack traces to API clients.
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hash_password(creds.password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Unable to create account")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    if row is None or not verify_password(creds.password, row["password"]):
        # Same response for unknown username and wrong password.
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": make_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user["id"]),
    ).fetchone()
    if row is None:
        # Do not reveal whether another user's note exists.
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
