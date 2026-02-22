import subprocess
import shutil
import os
import re
import threading
from database import get_conn, get_cursor

# John the Ripper configuration — auto-detect best available binary
_LOCAL_RUN_DIR = os.getenv("JOHN_RUN_DIR", "/app/john-bleeding-jumbo/run")
_LOCAL_JOHN_BIN = os.path.join(_LOCAL_RUN_DIR, "john")
_SYSTEM_JOHN_BIN = shutil.which("john") or "/usr/sbin/john"

# Use local bleeding-jumbo if available and executable, else fall back to system john
if os.path.isfile(_LOCAL_JOHN_BIN) and os.access(_LOCAL_JOHN_BIN, os.X_OK):
    JOHN_BIN = _LOCAL_JOHN_BIN
    JOHN_DIR = _LOCAL_RUN_DIR
    PDF2JOHN = os.path.join(JOHN_DIR, "pdf2john.pl")
else:
    # System john — pdf2john.pl is in /usr/share/john/
    JOHN_BIN = _SYSTEM_JOHN_BIN
    JOHN_DIR = os.path.dirname(JOHN_BIN)
    PDF2JOHN = "/usr/share/john/pdf2john.pl"

WORDLIST = os.path.join(_LOCAL_RUN_DIR, "password.lst") if os.path.isdir(_LOCAL_RUN_DIR) else "/usr/share/john/password.lst"
ROCKYOU = os.path.join(_LOCAL_RUN_DIR, "rockyou.txt")

print(f"[JTR] Using binary: {JOHN_BIN}")
print(f"[JTR] Using pdf2john: {PDF2JOHN}")


def update_job(job_id: int, status: str, password: str = None, fail_reason: str = None):
    conn = get_conn()
    cur = get_cursor(conn)
    if password:
        cur.execute(
            "UPDATE crack_jobs SET status=%s, cracked_password=%s, fail_reason=NULL, updated_at=NOW() WHERE id=%s",
            (status, password, job_id),
        )
    elif fail_reason:
        cur.execute(
            "UPDATE crack_jobs SET status=%s, fail_reason=%s, updated_at=NOW() WHERE id=%s",
            (status, fail_reason, job_id),
        )
    else:
        cur.execute(
            "UPDATE crack_jobs SET status=%s, updated_at=NOW() WHERE id=%s",
            (status, job_id),
        )
    cur.close()
    conn.close()


def run_crack_job(job_id: int, pdf_path: str, hash_path: str):
    """Run John the Ripper in background thread to crack a PDF password."""
    try:
        update_job(job_id, "extracting_hash")

        # Step 1: pdf2john.pl to extract hash
        result = subprocess.run(
            ["perl", PDF2JOHN, pdf_path],
            capture_output=True, text=True, timeout=60, cwd=JOHN_DIR
        )

        if result.returncode != 0 or not result.stdout.strip():
            reason = "PDF is not password protected" if not result.stdout.strip() else f"Hash extraction failed: {result.stderr[:200]}"
            update_job(job_id, "failed", fail_reason=reason)
            print(f"[Job {job_id}] pdf2john failed: {result.stderr}")
            return

        with open(hash_path, "w") as hf:
            hf.write(result.stdout.strip() + "\n")

        update_job(job_id, "cracking")

        # Step 2: Try with password.lst first (faster)
        cracked = _try_crack(job_id, hash_path, WORDLIST)

        # Step 3: If not cracked, try with rockyou.txt
        if not cracked and os.path.exists(ROCKYOU):
            print(f"[Job {job_id}] Trying rockyou.txt wordlist...")
            cracked = _try_crack(job_id, hash_path, ROCKYOU)

        # Step 4: Try john's default mode (single + incremental) — most powerful
        if not cracked:
            print(f"[Job {job_id}] Trying john default mode (brute force)...")
            cracked = _try_crack_default(job_id, hash_path)

        if cracked:
            update_job(job_id, "cracked", cracked)
            print(f"[Job {job_id}] Password cracked: {cracked}")
        else:
            update_job(job_id, "failed", fail_reason="Password not found — too complex for current wordlists")
            print(f"[Job {job_id}] Could not crack password")

    except Exception as e:
        print(f"[Job {job_id}] ERROR: {e}")
        update_job(job_id, "failed", fail_reason=f"Unexpected error: {str(e)[:200]}")


def _try_crack_default(job_id: int, hash_path: str) -> str | None:
    """Try cracking using john's default mode (single + incremental brute force).
    This is equivalent to just running: ./john pdf.hash
    Much more powerful than wordlist-only attacks but takes longer.
    """
    try:
        # Run john with no wordlist — uses single crack mode, then incremental
        subprocess.run(
            [JOHN_BIN, hash_path],
            capture_output=True, text=True, timeout=1800, cwd=JOHN_DIR  # 30 min max
        )
        # Check result
        show_result = subprocess.run(
            [JOHN_BIN, "--show", hash_path],
            capture_output=True, text=True, timeout=30, cwd=JOHN_DIR
        )
        return _parse_show_output(show_result.stdout)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John default mode timed out (30 min)")
        # Still check if it cracked something before timing out
        try:
            show_result = subprocess.run(
                [JOHN_BIN, "--show", hash_path],
                capture_output=True, text=True, timeout=10, cwd=JOHN_DIR
            )
            return _parse_show_output(show_result.stdout)
        except Exception:
            return None


def _try_crack(job_id: int, hash_path: str, wordlist: str) -> str | None:
    """Try cracking hash with given wordlist. Returns password or None."""
    try:
        # First check if already cracked (john.pot)
        show_result = subprocess.run(
            [JOHN_BIN, "--show", hash_path],
            capture_output=True, text=True, timeout=30, cwd=JOHN_DIR
        )
        password = _parse_show_output(show_result.stdout)
        if password:
            return password

        # Run john to crack
        subprocess.run(
            [JOHN_BIN, hash_path, f"--wordlist={wordlist}"],
            capture_output=True, text=True, timeout=600, cwd=JOHN_DIR
        )

        # Check result
        show_result = subprocess.run(
            [JOHN_BIN, "--show", hash_path],
            capture_output=True, text=True, timeout=30, cwd=JOHN_DIR
        )
        return _parse_show_output(show_result.stdout)

    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John timed out with {wordlist}")
        return None


def _parse_show_output(output: str) -> str | None:
    """Parse 'john --show' output to extract password.
    Output format: /path/to/hash.file:PASSWORD:uid:gid:gecos:home:shell
    Example: /app/app/uploads/abc_kavin.pdf:22022657
    """
    print(f"[JTR] --show output: {repr(output[:300])}")
    for line in output.splitlines():
        line = line.strip()
        # Skip summary lines like "0 password hashes cracked" or "1 password hash cracked"
        if not line or line[0].isdigit():
            continue
        # Skip other info lines
        if "password hash" in line.lower() or "No password" in line:
            continue
        # Real password lines: /path/to/file:password[:other:fields]
        if ":" in line:
            # Split only on first occurrence after the path - paths can have colons on Windows
            # But on Linux: /path:PASSWORD:...
            parts = line.split(":")
            if len(parts) >= 2:
                password = parts[1].strip()
                if password:
                    print(f"[JTR] Found password: {password}")
                    return password
    return None


def start_crack_thread(job_id: int, pdf_path: str, hash_path: str):
    """Start crack job in background thread."""
    t = threading.Thread(
        target=run_crack_job,
        args=(job_id, pdf_path, hash_path),
        daemon=True
    )
    t.start()
    return t
