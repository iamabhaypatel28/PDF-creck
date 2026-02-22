import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

def get_conn():
    # Priority 1: Use a central DATABASE_URL connection string (Neon.tech / Render)
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        conn = psycopg2.connect(db_url)
    else:
        # Priority 2: Use individual DB_ environment variables with Neon defaults
        DB_CONFIG = {
            "host": os.getenv("DB_HOST", "ep-dark-heart-afjb1ngx-pooler.c-2.us-west-2.aws.neon.tech"),
            "port": int(os.getenv("DB_PORT", "5432")),
            "database": os.getenv("DB_NAME", "neondb"),
            "user": os.getenv("DB_USER", "neondb_owner"),
            "password": os.getenv("DB_PASSWORD", "npg_i0AWewloLZg2"),
        }
        conn = psycopg2.connect(**DB_CONFIG)
    
    conn.autocommit = True
    return conn


def get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    """Create tables if they don't exist."""
    conn = get_conn()
    cur = get_cursor(conn)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS magic_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            token UUID DEFAULT gen_random_uuid(),
            expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '30 minutes',
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS crack_jobs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            original_name VARCHAR(500) NOT NULL,
            pdf_filename VARCHAR(500) NOT NULL,
            hash_file VARCHAR(500),
            status VARCHAR(50) DEFAULT 'pending',
            cracked_password VARCHAR(500),
            fail_reason TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Add fail_reason column if it doesn't exist (for already-deployed DBs)
    try:
        cur.execute("ALTER TABLE crack_jobs ADD COLUMN IF NOT EXISTS fail_reason TEXT;")
    except Exception:
        pass  # Column already exists
    cur.close()
    conn.close()
