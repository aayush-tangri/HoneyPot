from __future__ import annotations

import os
import time
import uuid
import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, Form, Request, UploadFile, Response
from fastapi.middleware.cors import CORSMiddleware

from app.core.log_writer import append_jsonl
from app.core.terminal import _c, print_request, print_attack
from app.services.detection_engine import DetectionEngine


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.abspath(os.path.join(APP_ROOT, ".."))
LOG_PATH = os.path.join(BACKEND_ROOT, "logs", "requests.jsonl")
UPLOAD_DIR = os.path.join(BACKEND_ROOT, "uploads")

# In-memory behavior engine (rule-first).
ENGINE = DetectionEngine()

# ── Startup banner ─────────────────────────────────────────────────────────────
print(_c("\n╔══════════════════════════════════════════════════════╗", "1;96"))
print(_c("║        HoneyGuard — Honeypot Backend Running        ║", "1;96"))
print(_c("╚══════════════════════════════════════════════════════╝", "1;96"))
ml_status = _c("✓ ML classifier ready (Random Forest)", "92") if ENGINE._classifier_ready else _c("✗ ML unavailable — rules only", "93")
print(f"  {ml_status}")
print(_c("  Listening for attacks...\n", "90"))


app = FastAPI(
    title="Intelligent Honeypot Backend",
    version="0.1.0",
    description=(
        "Intentionally vulnerable honeypot API.\n\n"
        "WARNING: Vulnerabilities are intentional for security research."
    ),
)

# Allow the existing Vite frontend to call the backend locally.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Non-negotiable: structured JSON request telemetry.
@app.middleware("http")
async def structured_request_logger(request: Request, call_next):
    """
    Non-negotiable telemetry layer:
    - Logs *every* request as structured JSON (JSONL).
    - Fields match the required schema from the project brief.
    """
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    start = time.perf_counter()
    body = await request.body()
    payload_size = len(body) if body else 0

    xff = request.headers.get("x-forwarded-for")
    ip = (xff.split(",")[0].strip() if xff else None) or (request.client.host if request.client else None) or "unknown"
    user_agent = request.headers.get("user-agent", "")

    status_code = 500
    auth_success = None

    try:
        response: Response = await call_next(request)
        status_code = response.status_code
        auth_success = getattr(request.state, "auth_success", None)
        return response
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)

        # IMPORTANT: log_writer will stamp the final timestamp at write-time.
        # We keep this field present here for schema clarity, but allow the writer
        # to be the single source of truth.
        event = {
            "timestamp": None,
            "ip": ip,
            "endpoint": str(request.url.path),
            "method": request.method,
            "status_code": status_code,
            "auth_success": auth_success,
            "response_time_ms": duration_ms,
            "payload_size": payload_size,
            "user_agent": user_agent,
            "request_id": request_id,
        }

        # ── Print every request to terminal ───────────────────────────────────
        if request.url.path not in ("/health", "/favicon.ico"):
            print_request(ip, request.method, str(request.url.path), status_code, duration_ms)

        try:
            await append_jsonl(LOG_PATH, event)
        except Exception:
            # Logging must never break the honeypot.
            pass

        # Also feed the in-memory detector immediately (so UI updates without waiting).
        try:
            # Ensure timestamp is present for rule windows.
            event["timestamp"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            ENGINE.process_request_event(event)
        except Exception:
            pass


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True}


# -----------------------------
# Honeypot vulnerable endpoints
# -----------------------------

# NOTE: These vulnerabilities are intentional and should be documented in viva:
# - POST /login: no rate limiting -> brute force possible
# - GET /api/users/{id}: IDOR -> no ownership check
# - POST /api/upload: weak validation
# - GET /api/admin/stats: broken RBAC (no real authorization)

_DEMO_USERS = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
    3: {"id": 3, "username": "admin", "email": "admin@example.com", "role": "admin"},
}

# Intentionally simplistic credential store (do NOT harden).
_CREDENTIALS = {
    "alice": "password123",
    "bob": "qwerty",
    "admin": "admin",
}


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Dict[str, Any]:
    """
    Intentionally vulnerable:
    - No rate limiting / lockout.
    - Returns generic success/failure with no protective measures.
    """
    expected = _CREDENTIALS.get(username)
    ok = expected is not None and expected == password
    request.state.auth_success = ok
    # Optional extra telemetry (allowed beyond required schema).
    request.state.login_username = username

    if ok:
        # No real sessions/token security (honeypot).
        return {"success": True, "message": "Login successful", "user": {"username": username}}
    return {"success": False, "message": "Invalid credentials"}


@app.get("/api/users/{id}")
async def get_user(id: int) -> Dict[str, Any]:
    """
    IDOR (Insecure Direct Object Reference):
    - No ownership check.
    - Any requester can fetch any user by ID.
    """
    user = _DEMO_USERS.get(id)
    if not user:
        return {"error": "User not found"}
    return {"user": user}


@app.post("/api/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    note: Optional[str] = Form(None),
) -> Dict[str, Any]:
    """
    Weak validation:
    - Accepts any file type.
    - Stores by original filename (unsafe by design for honeypot realism).
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    dest = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()

    with open(dest, "wb") as f:
        f.write(content)

    return {
        "success": True,
        "stored_as": file.filename,
        "bytes": len(content),
        "note": note,
        "request_id": getattr(request.state, "request_id", None),
    }


@app.get("/api/admin/stats")
async def admin_stats() -> Dict[str, Any]:
    """
    Broken RBAC:
    - No authorization check. Anyone can call this.
    """
    return {
        "users": len(_DEMO_USERS),
        "uploads_dir": "uploads/",
        "message": "Admin stats (intentionally exposed)",
    }


# -----------------------------------
# Frontend dashboard feed endpoints
# -----------------------------------
# These will be upgraded in later phases to come from rule+ML engines.


@app.get("/api/attacks")
async def api_attacks(limit: int = 50) -> Dict[str, Any]:
    """
    Returns recent 'attack events'.
    Rule-engine output (behavior-first), not raw logs.
    """
    # If server restarted, backfill from existing log file once lazily.
    try:
        ENGINE.tail_once(LOG_PATH)
    except Exception:
        pass
    return {"attacks": ENGINE.get_recent_attacks(limit)}


@app.get("/api/attacker/{ip}")
async def api_attacker_profile(ip: str) -> Dict[str, Any]:
    try:
        ENGINE.tail_once(LOG_PATH)
    except Exception:
        pass
    return ENGINE.get_attacker_profile(ip)


@app.get("/api/analytics")
async def api_analytics() -> Dict[str, Any]:
    """
    Returns aggregated analytics used by the dashboard charts.
    Shapes match frontend mockData helpers:
    - attackTypeDistribution: [{name, value}]
    - topEndpoints: [{endpoint, attacks}]
    - hourlyAttackVolume: [{hour, attacks}]
    """
    try:
        ENGINE.tail_once(LOG_PATH)
    except Exception:
        pass
    return ENGINE.get_analytics()

