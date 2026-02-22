import subprocess
import shutil
import os
import re
import threading
from database import get_conn, get_cursor

JOHN_DIR = "/home/abhay/Work p/pdf creck/john-bleeding-jumbo/run"
JOHN_BIN = os.path.join(JOHN_DIR, "john")
PDF2JOHN = os.path.join(JOHN_DIR, "pdf2john.pl")
WORDLIST = os.path.join(JOHN_DIR, "password.lst")
ROCKYOU = os.path.join(JOHN_DIR, "rockyou.txt")


def update_job(job_id: int, status: str, password: str = None):
    conn = get_conn()
    cur = get_cursor(conn)
    if password:
        cur.execute(
            "UPDATE crack_jobs SET status=%s, cracked_password=%s, updated_at=NOW() WHERE id=%s",
            (status, password, job_id),
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
        with open(hash_path, "w") as hf:
            result = subprocess.run(
                ["perl", PDF2JOHN, pdf_path],
                capture_output=True, text=True, timeout=60, cwd=JOHN_DIR
            )
        
        if result.returncode != 0 or not result.stdout.strip():
            update_job(job_id, "failed")
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

        if cracked:
            update_job(job_id, "cracked", cracked)
            print(f"[Job {job_id}] Password cracked: {cracked}")
        else:
            update_job(job_id, "failed")
            print(f"[Job {job_id}] Could not crack password")

    except Exception as e:
        print(f"[Job {job_id}] ERROR: {e}")
        update_job(job_id, "failed")


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
    Output format: filename:password:..."""
    for line in output.splitlines():
        if ":" in line and not line.startswith("0 ") and not line.startswith("1 "):
            parts = line.split(":")
            if len(parts) >= 2:
                password = parts[1].strip()
                if password:
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
