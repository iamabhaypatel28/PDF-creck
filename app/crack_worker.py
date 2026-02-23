import subprocess
import shutil
import os
import re
import threading
from database import get_conn, get_cursor

# ANSI escape code stripper (for clean passwords)
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# John the Ripper configuration — prioritized compiled jumbo version
# Dynamic path detection for Local vs Docker
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCAL_RUN_DIR = os.path.join(_BASE_DIR, "john-bleeding-jumbo", "run")

_LOCAL_JOHN_BIN = os.path.join(_LOCAL_RUN_DIR, "john")
_LOCAL_PDF2JOHN = os.path.join(_LOCAL_RUN_DIR, "pdf2john.pl")
_SYSTEM_JOHN_BIN = shutil.which("john") or "/usr/sbin/john"

def _print_debug_info():
    """Print deep debug info for live environment troubleshooting."""
    print("[DEBUG-LIVE] --- System Info ---")
    try:
        print(f"[DEBUG-LIVE] User: {subprocess.check_output(['whoami'], text=True).strip()}")
        print(f"[DEBUG-LIVE] PWD: {os.getcwd()}")
        print(f"[DEBUG-LIVE] Base Dir: {_BASE_DIR}")
        print(f"[DEBUG-LIVE] Local Run Dir: {_LOCAL_RUN_DIR}")
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r") as f:
                cpu = [line for line in f if "model name" in line]
                if cpu: print(f"[DEBUG-LIVE] CPU: {cpu[0].split(':')[1].strip()}")
    except Exception as e:
        print(f"[DEBUG-LIVE] Debug info error: {e}")

def _test_binary(path: str) -> bool:
    """Check if a john binary actually runs."""
    if not os.path.exists(path):
        return False
    try:
        # Check ldd for missing libs (optional, helps debug)
        subprocess.run(["ldd", path], capture_output=True, text=True)
        # Test execution
        result = subprocess.run([path], capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        return "John the Ripper" in output or "Unknown option" in output or "Usage:" in output
    except Exception:
        return False

_print_debug_info()

# Priority 1: Compiled Jumbo version (optimized for this CPU)
if _test_binary(_LOCAL_JOHN_BIN):
    JOHN_BIN = _LOCAL_JOHN_BIN
    JOHN_DIR = _LOCAL_RUN_DIR
    print(f"[JTR] Success! Using compiled jumbo binary: {JOHN_BIN}")
else:
    # Priority 2: System john fallback
    JOHN_BIN = _SYSTEM_JOHN_BIN
    JOHN_DIR = os.path.dirname(JOHN_BIN) if JOHN_BIN else "/usr/sbin"
    print(f"[JTR] Falling back to system john: {JOHN_BIN}")

# Always prefer the jumbo pdf2john.pl perl script (supports more formats)
if os.path.isfile(_LOCAL_PDF2JOHN):
    PDF2JOHN = _LOCAL_PDF2JOHN
else:
    # System fallback paths
    SYSTEM_PDF2JOHN = "/usr/share/john/pdf2john.pl"
    if not os.path.isfile(SYSTEM_PDF2JOHN):
        SYSTEM_PDF2JOHN = "/usr/sbin/pdf2john" # Common on some Ubuntu distros
    PDF2JOHN = SYSTEM_PDF2JOHN

# Pot file location (writable)
POT_FILE = os.path.join(_BASE_DIR, "app", "uploads", "john.pot")

print(f"[JTR] Loaded pdf2john: {PDF2JOHN}")
print(f"[JTR] Using pot file: {POT_FILE}")
WORDLIST = os.path.join(_LOCAL_RUN_DIR, "password.lst")
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

        # Step 1.5: Immediate check — is it already in the pot? (FAST RECOVERY)
        print(f"[Job {job_id}] Checking if hash is already cracked...")
        cracked = _check_pot(hash_path)
        
        if not cracked:
            # Step 2: Try with small wordlist first (password.lst)
            cracked = _try_crack(job_id, hash_path, WORDLIST)

        # Step 3: Try numeric brute force (FAST and SUCCESSFUL for digits like 123456)
        if not cracked:
            print(f"[Job {job_id}] Trying specialized numeric brute-force...")
            cracked = _try_numeric(job_id, hash_path)

        # Step 4: Try with rockyou.txt (Slow, millions of passwords)
        if not cracked and os.path.exists(ROCKYOU):
            print(f"[Job {job_id}] Trying rockyou.txt wordlist...")
            cracked = _try_crack(job_id, hash_path, ROCKYOU)

        # Step 5: Try john's default mode (full brute force)
        if not cracked:
            print(f"[Job {job_id}] Trying john default mode (full brute force)...")
            cracked = _try_crack_default(job_id, hash_path)

        # Final check: In case it cracked but stdout was messy
        if not cracked:
            cracked = _check_pot(hash_path)

        if cracked:
            update_job(job_id, "cracked", cracked)
            print(f"[Job {job_id}] Password cracked: {cracked}")
        else:
            update_job(job_id, "failed", fail_reason="Password not found — too complex for current wordlists")
            print(f"[Job {job_id}] Could not crack password")

    except Exception as e:
        print(f"[Job {job_id}] ERROR: {e}")
        update_job(job_id, "failed", fail_reason=f"Unexpected error: {str(e)[:200]}")


def _check_pot(hash_path: str) -> str | None:
    """Check if hash is already cracked using john --show."""
    try:
        result = subprocess.run(
            [JOHN_BIN, "--show", hash_path, f"--pot={POT_FILE}"],
            capture_output=True, text=True, timeout=10, cwd=JOHN_DIR
        )
        return _parse_show_output(result.stdout)
    except Exception:
        return None


def _try_crack_default(job_id: int, hash_path: str) -> str | None:
    """Try cracking using john's default mode (single + incremental brute force)."""
    try:
        result = subprocess.run(
            [JOHN_BIN, hash_path, f"--pot={POT_FILE}"],
            capture_output=True, text=True, timeout=1800, cwd=JOHN_DIR
        )
        return _parse_john_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John default mode timed out")
        return None

def _try_numeric(job_id: int, hash_path: str) -> str | None:
    """Try specialized numeric incremental mode (very fast for passwords like 22022657)."""
    try:
        # Use incremental=digits mode which is built-in for most JTR builds
        result = subprocess.run(
            [JOHN_BIN, hash_path, "--incremental=digits", f"--pot={POT_FILE}"],
            capture_output=True, text=True, timeout=600, cwd=JOHN_DIR
        )
        print(f"[JTR] numeric mode stdout: {repr(result.stdout[:400])}")
        print(f"[JTR] numeric mode stderr: {repr(result.stderr[:400])}")
        return _parse_john_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John numeric mode timed out")
        return None


def _try_crack(job_id: int, hash_path: str, wordlist: str) -> str | None:
    """Try cracking hash with given wordlist. Parses john's DIRECT stdout."""
    try:
        result = subprocess.run(
            [JOHN_BIN, hash_path, f"--wordlist={wordlist}", f"--pot={POT_FILE}"],
            capture_output=True, text=True, timeout=600, cwd=JOHN_DIR
        )
        print(f"[JTR] wordlist stdout: {repr(result.stdout[:400])}")
        print(f"[JTR] wordlist stderr: {repr(result.stderr[:200])}")
        return _parse_john_output(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Job {job_id}] John timed out with {wordlist}")
        return None


def _parse_john_output(output: str) -> str | None:
    """Parse john's cracked password from stdout/stderr."""
    if not output:
        return None
        
    # Strip colors first
    clean_text = ANSI_ESCAPE.sub('', output)
    
    # Pattern: PASSWORD          (/path/to/file)
    pattern = re.compile(r'^(.+?)\s{2,}\(.*\)\s*$', re.MULTILINE)
    for match in pattern.finditer(clean_text):
        candidate = match.group(1).strip()
        # Filter out status/usage lines
        if candidate and not any(x in candidate for x in ['Press', 'Loaded', 'Remaining', 'Usage:']):
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
