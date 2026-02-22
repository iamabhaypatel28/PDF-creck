import subprocess
import shutil
import os
import re
import threading
from database import get_conn, get_cursor

# John the Ripper configuration — test-run to find best working binary
_LOCAL_RUN_DIR = os.getenv("JOHN_RUN_DIR", "/app/john-bleeding-jumbo/run")
_LOCAL_JOHN_BIN = os.path.join(_LOCAL_RUN_DIR, "john")
_SYSTEM_JOHN_BIN = shutil.which("john") or "/usr/sbin/john"

def _test_binary(path: str) -> bool:
    """Check if a john binary actually runs (not just exists)."""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

# Use local bleeding-jumbo ONLY if it actually works (no GLIBC/OpenSSL mismatch)
if os.path.isfile(_LOCAL_JOHN_BIN) and os.access(_LOCAL_JOHN_BIN, os.X_OK) and _test_binary(_LOCAL_JOHN_BIN):
    JOHN_BIN = _LOCAL_JOHN_BIN
    JOHN_DIR = _LOCAL_RUN_DIR
    PDF2JOHN = os.path.join(JOHN_DIR, "pdf2john.pl")
    print(f"[JTR] Using bleeding-jumbo binary: {JOHN_BIN}")
else:
    # System john — compatible with Docker environment
    JOHN_BIN = _SYSTEM_JOHN_BIN
    JOHN_DIR = os.path.dirname(JOHN_BIN) if JOHN_BIN else "/usr/sbin"
    PDF2JOHN = "/usr/share/john/pdf2john.pl"
    print(f"[JTR] Falling back to system john: {JOHN_BIN}")

print(f"[JTR] Using pdf2john: {PDF2JOHN}")
WORDLIST = os.path.join(_LOCAL_RUN_DIR, "password.lst") if os.path.isdir(_LOCAL_RUN_DIR) else "/usr/share/john/password.lst"
ROCKYOU = os.path.join(_LOCAL_RUN_DIR, "rockyou.txt")


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
    Parses john's DIRECT stdout to extract cracked password.
    """
    try:
        result = subprocess.run(
            [JOHN_BIN, hash_path],
            capture_output=True, text=True, timeout=1800, cwd=JOHN_DIR
        )
        print(f"[JTR] default mode stdout: {repr(result.stdout[:400])}")
        print(f"[JTR] default mode stderr: {repr(result.stderr[:400])}")
        return _parse_john_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John default mode timed out")
        return None


def _try_crack(job_id: int, hash_path: str, wordlist: str) -> str | None:
    """Try cracking hash with given wordlist. Parses john's DIRECT stdout."""
    try:
        result = subprocess.run(
            [JOHN_BIN, hash_path, f"--wordlist={wordlist}"],
            capture_output=True, text=True, timeout=600, cwd=JOHN_DIR
        )
        print(f"[JTR] wordlist stdout: {repr(result.stdout[:400])}")
        print(f"[JTR] wordlist stderr: {repr(result.stderr[:200])}")
        return _parse_john_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John timed out with {wordlist}")
        return None


def _parse_john_output(output: str) -> str | None:
    """Parse john's direct stdout/stderr to extract cracked password.
    John prints cracked passwords in format:
      PASSWORD          (/path/to/file)
    or:
      PASSWORD          (/path/to/file)    (raw hash)
    """
    print(f"[JTR] Parsing output: {repr(output[:500])}")
    import re
    # Pattern: anything followed by whitespace and (filename) at end of line
    pattern = re.compile(r'^(.+?)\s{2,}\(.*\)\s*$', re.MULTILINE)
    for match in pattern.finditer(output):
        candidate = match.group(1).strip()
        # Filter out john status lines
        if candidate and not candidate.startswith('Press') and not candidate.startswith('Loaded') and not candidate.startswith('Remaining'):
            print(f"[JTR] Cracked password found: {candidate}")
            return candidate
    return None


def _parse_show_output(output: str) -> str | None:
    """Legacy: Parse 'john --show' output. Kept for compatibility."""
    print(f"[JTR] --show output: {repr(output[:300])}")
    for line in output.splitlines():
        line = line.strip()
        if not line or line[0].isdigit():
            continue
        if 'password hash' in line.lower() or 'No password' in line:
            continue
        if ':' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                password = parts[1].strip()
                if password:
                    print(f"[JTR] Found password via --show: {password}")
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
