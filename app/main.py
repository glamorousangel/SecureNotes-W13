
"""
SecureNotes API — Week 13 Security Lab
"""

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel


# --- app + config -----------------------------------------------------------

app = FastAPI(title="SecureNotes API", version="1.0")

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

security = HTTPBearer(auto_error=False)


# --- database ----------------------------

db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


# --- password security ------------------------------------------------------

def hash_password(password: str, salt: bytes | None = None) -> str:
    """Return a salted PBKDF2 password hash."""
    salt = salt or secrets.token_bytes(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100_000,
    )

    return (
        f"{base64.urlsafe_b64encode(salt).decode()}$"
        f"{base64.urlsafe_b64encode(derived).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify a password securely."""
    try:
        salt_b64, hash_b64 = stored.split("$", 1)

        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(hash_b64.encode())

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100_000,
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError, binascii.Error):
        return False


# --- token generation and validation ---------------------------------------

def make_token(user_id: int) -> str:
    """Create a signed token containing a user ID and expiration time."""
    expires = int(time.time()) + 3600
    payload = f"{user_id}:{expires}".encode()

    signature = hmac.new(
        SECRET_KEY.encode(),
        payload,
        hashlib.sha256,
    ).digest()

    encoded_payload = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    encoded_signature = (
        base64.urlsafe_b64encode(signature).decode().rstrip("=")
    )

    return f"{encoded_payload}.{encoded_signature}"


def decode_base64(value: str) -> bytes:
    """Decode URL-safe Base64 with the required padding."""
    padded_value = value + "=" * (-len(value) % 4)
    return base64.b64decode(
        padded_value,
        altchars=b"-_",
        validate=True,
    )


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    """Validate the bearer token and return the authenticated user."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        encoded_payload, encoded_signature = token.split(".")

        payload = decode_base64(encoded_payload)
        signature = decode_base64(encoded_signature)

        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            payload,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature")

        user_id_text, expires_text = payload.decode().split(":", 1)

        user_id = int(user_id_text)
        expires = int(expires_text)

        if user_id <= 0 or int(time.time()) >= expires:
            raise ValueError("Invalid or expired token")

    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        binascii.Error,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    row = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return row


# --- database initialization ------------------------------------------------

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
            body TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )

    # Seed accounts. Passwords are stored as salted hashes.
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("admin", hash_password("admin123"), 1),
    )

    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("alice", hash_password("alicepass"), 0),
    )

    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("bob", hash_password("bobpass"), 0),
    )

    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (2, "Alice diary", "Alice secret note"),
    )

    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (3, "Bob plans", "Bob secret note"),
    )

    db.commit()


init_db()


# --- request models ---------------------------------------------------------

class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- error handling ---------------------------------------------------------

@app.exception_handler(Exception)
async def handle_everything(request, exc):
    """Avoid exposing unexpected internal exception details."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# --- public routes ----------------------------------------------------------

@app.get("/")
def home():
    return {
        "service": "SecureNotes API",
        "docs": "/docs",
    }


@app.post("/register")
def register(creds: Credentials):
    try:
        db.execute(
            """
            INSERT INTO users (username, password, is_admin)
            VALUES (?, ?, 0)
            """,
            (creds.username, hash_password(creds.password)),
        )
        db.commit()

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="Unable to create account",
        )

    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()

    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    return {"token": make_token(row["id"])}


# --- protected note routes --------------------------------------------------

@app.get("/notes")
def list_my_notes(user=Depends(current_user)):
    rows = db.execute(
        "SELECT * FROM notes WHERE owner_id = ?",
        (user["id"],),
    ).fetchall()

    return [dict(row) for row in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    row = db.execute(
        """
        SELECT * FROM notes
        WHERE id = ? AND owner_id = ?
        """,
        (note_id, user["id"]),
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, user=Depends(current_user)):
    cur = db.execute(
        """
        INSERT INTO notes (owner_id, title, body)
        VALUES (?, ?, ?)
        """,
        (user["id"], note.title, note.body),
    )

    db.commit()

    return {
        "id": cur.lastrowid,
        "title": note.title,
    }


# --- admin-only route -------------------------------------------------------

@app.get("/admin/users")
def list_all_users(user=Depends(current_user)):
    if not user["is_admin"]:
        raise HTTPException(
            status_code=403,
            detail="Admins only",
        )

    rows = db.execute(
        "SELECT id, username, is_admin FROM users"
    ).fetchall()

    return [dict(row) for row in rows]