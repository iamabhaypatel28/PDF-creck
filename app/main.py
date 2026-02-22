import os
import uuid
import shutil
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import get_conn, get_cursor, init_db
from auth import (
    get_or_create_user, create_magic_token, verify_magic_token,
    create_jwt, decode_jwt
)
from crack_worker import start_crack_thread

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

app = FastAPI(title="PDF Password Cracker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    init_db()


# ─────────────────────────────────────────────
#  Static files
# ─────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# ─────────────────────────────────────────────
#  Auth helpers
# ─────────────────────────────────────────────
def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ", 1)[1]
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# ─────────────────────────────────────────────
#  Pages
# ─────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(os.path.dirname(__file__), "static", "index.html")) as f:
        return f.read()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(os.path.dirname(__file__), "static", "dashboard.html")) as f:
        return f.read()


# ─────────────────────────────────────────────
#  Auth endpoints
# ─────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str


@app.post("/auth/request-login")
def request_login(body: LoginRequest):
    # Directly create/get user and return JWT — no magic link needed
    user = get_or_create_user(body.email)
    jwt_token = create_jwt(user["id"], body.email)
    return {
        "token": jwt_token,
        "email": body.email,
    }



@app.get("/auth/verify")
def verify_login(token: str):
    row = verify_magic_token(token)
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired magic link")
    jwt_token = create_jwt(row["user_id"], row["email"])
    # Redirect to dashboard with token embedded in URL hash
    return RedirectResponse(url=f"/dashboard#token={jwt_token}")


MAX_JOBS_PER_USER = 5

# ─────────────────────────────────────────────
#  Crack Jobs
# ─────────────────────────────────────────────
def _delete_job_files(job: dict):
    """Delete PDF and hash files for a job from disk."""
    for key in ("pdf_filename", "hash_file"):
        path = job.get(key)
        if not path:
            continue
        # pdf_filename is just the filename; hash_file is full path
        full_path = path if os.path.isabs(path) else os.path.join(UPLOAD_DIR, path)
        try:
            if os.path.exists(full_path):
                os.remove(full_path)
        except Exception as e:
            print(f"[cleanup] Could not delete {full_path}: {e}")


@app.post("/jobs/upload")
def upload_pdf(
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    user_id = int(user["sub"])

    conn = get_conn()
    cur = get_cursor(conn)

    # ── Enforce 5-job limit: delete oldest if at limit ──────────────────
    cur.execute(
        "SELECT id, pdf_filename, hash_file FROM crack_jobs WHERE user_id = %s ORDER BY created_at ASC",
        (user_id,),
    )
    existing_jobs = cur.fetchall()

    if len(existing_jobs) >= MAX_JOBS_PER_USER:
        # Delete oldest jobs until we're under the limit (usually just 1)
        jobs_to_delete = existing_jobs[: len(existing_jobs) - MAX_JOBS_PER_USER + 1]
        for old_job in jobs_to_delete:
            _delete_job_files(dict(old_job))
            cur.execute("DELETE FROM crack_jobs WHERE id = %s", (old_job["id"],))
        print(f"[upload] Removed {len(jobs_to_delete)} old job(s) for user {user_id}")

    # ── Save new PDF ─────────────────────────────────────────────────────
    job_id_prefix = str(uuid.uuid4())[:8]
    safe_filename = f"{job_id_prefix}_{file.filename}"
    pdf_path = os.path.join(UPLOAD_DIR, safe_filename)
    hash_path = pdf_path.replace(".pdf", ".hsh")

    with open(pdf_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    cur.execute(
        """
        INSERT INTO crack_jobs (user_id, original_name, pdf_filename, hash_file, status)
        VALUES (%s, %s, %s, %s, 'pending') RETURNING id
        """,
        (user_id, file.filename, safe_filename, hash_path),
    )
    row = cur.fetchone()
    job_id = row["id"]
    cur.close()
    conn.close()

    # Start background crack thread
    start_crack_thread(job_id, pdf_path, hash_path)

    return {"job_id": job_id, "status": "pending", "filename": file.filename}


@app.get("/jobs/")
def list_jobs(user: dict = Depends(get_current_user)):
    conn = get_conn()
    cur = get_cursor(conn)
    cur.execute(
        """
        SELECT id, original_name, status, cracked_password, fail_reason, created_at, updated_at
        FROM crack_jobs WHERE user_id = %s ORDER BY created_at DESC
        """,
        (int(user["sub"]),),
    )
    jobs = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    # Convert datetimes to strings
    for j in jobs:
        j["created_at"] = str(j["created_at"])
        j["updated_at"] = str(j["updated_at"])
    return jobs


@app.get("/jobs/{job_id}")
def get_job(job_id: int, user: dict = Depends(get_current_user)):
    conn = get_conn()
    cur = get_cursor(conn)
    cur.execute(
        "SELECT * FROM crack_jobs WHERE id = %s AND user_id = %s",
        (job_id, int(user["sub"])),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    job = dict(row)
    job["created_at"] = str(job["created_at"])
    job["updated_at"] = str(job["updated_at"])
    return job
