import json
import os
import sqlite3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any

app = FastAPI(title="Attendance Tracker Sync API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.environ.get("SQLITE_DB_PATH", "attendance_cloud_sync.db")
SEM1_START_DATE = "2026-09-07"
SEM1_LAST_INSTRUCTION_DATE = "2026-12-04"
EXAM_RANGES = [
    ("2026-10-19", "2026-10-24"),  # Mid-Semester Examination (MSE)
    ("2026-12-07", "2026-12-12"),  # Oral / Practical Examination
    ("2026-12-14", "2026-12-23"),  # End-Semester Examination (ESE)
]

ADMIN_EMAIL_SALTSHA256 = "fd59fa4b0e9158a4ef72be9a7459c5b4b8b8532a60b0f74a370623bc6b271357"
ADMIN_PW_SALTSHA256 = "a2eb4d78636647b59f87c3e45b18a431a6c27ff8df435364a85261e6401564a1"


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


def is_valid_instructional_date(iso: str) -> bool:
    if iso < SEM1_START_DATE or iso > SEM1_LAST_INSTRUCTION_DATE:
        return False
    for start, end in EXAM_RANGES:
        if start <= iso <= end:
            return False
    return True


def clean_non_instructional_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("dailyLogs", "dailyTicks", "slot7Map"):
        if isinstance(profile.get(key), dict):
            profile[key] = {
                iso: val
                for iso, val in profile[key].items()
                if is_valid_instructional_date(iso)
            }
    return profile


class UserSyncPayload(BaseModel):
    email: str
    passwordHash: str
    profile: Dict[str, Any]


class GlobalExtrasPayload(BaseModel):
    adminEmailHash: str
    adminPwHash: str
    extras: Dict[str, int]


@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "Attendance Tracker Cloud Sync Backend",
        "term_start": SEM1_START_DATE,
        "last_instruction_date": SEM1_LAST_INSTRUCTION_DATE,
    }


@app.post("/api/sync/push")
def push_user_state(data: UserSyncPayload):
    email = data.email.strip().lower()
    if not email.endswith("@gmail.com"):
        raise HTTPException(status_code=400, detail="Invalid Gmail address.")

    cleaned_profile = clean_non_instructional_profile(data.profile)

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
                (json.dumps(cleaned_profile), data.passwordHash, email),
            )
        else:
            cur.execute(
                "INSERT INTO users (email, password_hash, payload) VALUES (?, ?, ?)",
                (email, data.passwordHash, json.dumps(cleaned_profile)),
            )
        conn.commit()

    return {"ok": True, "email": email}


@app.post("/api/sync/pull")
def pull_user_state(data: UserSyncPayload):
    email = data.email.strip().lower()
    cleaned_incoming = clean_non_instructional_profile(data.profile)

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, payload FROM users WHERE email = ?", (email,))
        row = cur.fetchone()

        if row is None:
            cur.execute(
                "INSERT INTO users (email, password_hash, payload) VALUES (?, ?, ?)",
                (email, data.passwordHash, json.dumps(cleaned_incoming)),
            )
            conn.commit()
            return {"ok": True, "found": False, "profile": cleaned_incoming}

        stored_hash, payload_str = row
        if stored_hash and stored_hash != data.passwordHash:
            raise HTTPException(status_code=401, detail="Incorrect password for this account.")

        saved_profile = clean_non_instructional_profile(json.loads(payload_str))
        return {"ok": True, "found": True, "profile": saved_profile}


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
