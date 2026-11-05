import json
import os
import sqlite3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional

app = FastAPI(title="Attendance Tracker Sync API")

# Allow your GitHub Pages website (PC & Android) to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.environ.get("SQLITE_DB_PATH", "attendance_cloud_sync.db")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS global_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()


init_db()


class UserSyncPayload(BaseModel):
    email: str
    passwordHash: str
    profile: Dict[str, Any]


class GlobalExtrasPayload(BaseModel):
    adminEmailHash: str
    adminPwHash: str
    extras: Dict[str, int]


# Exact salted SHA-256 hashes (Zero plaintext email or password exposed)
ADMIN_EMAIL_SALTSHA256 = "fd59fa4b0e9158a4ef72be9a7459c5b4b8b8532a60b0f74a370623bc6b271357"
ADMIN_PW_SALTSHA256 = "a2eb4d78636647b59f87c3e45b18a431a6c27ff8df435364a85261e6401564a1"


@app.get("/")
def health_check():
    return {"status": "online", "service": "Attendance Tracker Cloud Sync Backend"}


@app.post("/api/sync/push")
def push_user_state(data: UserSyncPayload):
    email = data.email.strip().lower()
    if not email.endswith("@gmail.com"):
        raise HTTPException(status_code=400, detail="Invalid Gmail address.")

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()

        if row is not None:
            stored_hash = row[0]
            if stored_hash and stored_hash != data.passwordHash:
                raise HTTPException(status_code=401, detail="Incorrect password for this account.")
            cur.execute(
                "UPDATE users SET payload = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?",
                (json.dumps(data.profile), data.passwordHash, email),
            )
        else:
            cur.execute(
                "INSERT INTO users (email, password_hash, payload) VALUES (?, ?, ?)",
                (email, data.passwordHash, json.dumps(data.profile)),
            )
        conn.commit()

    return {"ok": True, "email": email}


@app.post("/api/sync/pull")
def pull_user_state(data: UserSyncPayload):
    email = data.email.strip().lower()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, payload FROM users WHERE email = ?", (email,))
        row = cur.fetchone()

        if row is None:
            # First time on server: register this profile automatically
            cur.execute(
                "INSERT INTO users (email, password_hash, payload) VALUES (?, ?, ?)",
                (email, data.passwordHash, json.dumps(data.profile)),
            )
            conn.commit()
            return {"ok": True, "found": False, "profile": data.profile}

        stored_hash, payload_str = row
        if stored_hash and stored_hash != data.passwordHash:
            raise HTTPException(status_code=401, detail="Incorrect password for this account.")

        return {"ok": True, "found": True, "profile": json.loads(payload_str)}


@app.get("/api/global-extras")
def get_global_extras():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM global_config WHERE key = 'admin_extras'")
        row = cur.fetchone()
        return {"extras": json.loads(row[0]) if row else {}}


@app.post("/api/global-extras")
def set_global_extras(data: GlobalExtrasPayload):
    if data.adminEmailHash != ADMIN_EMAIL_SALTSHA256 or data.adminPwHash != ADMIN_PW_SALTSHA256:
        raise HTTPException(status_code=403, detail="Unauthorized Admin credentials.")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO global_config (key, value) VALUES ('admin_extras', ?)",
            (json.dumps(data.extras),),
        )
        conn.commit()
    return {"ok": True, "extras": data.extras}
