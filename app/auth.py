import uuid
import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from database import get_conn, get_cursor

SECRET_KEY = os.getenv("SECRET_KEY", "pdf-crecker-super-secret-key-2024")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24


def get_or_create_user(email: str) -> dict:
    conn = get_conn()
    cur = get_cursor(conn)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    if not user:
        cur.execute(
            "INSERT INTO users (email) VALUES (%s) RETURNING *", (email,)
        )
        user = cur.fetchone()
    cur.close()
    conn.close()
    return dict(user)


def create_magic_token(user_id: int) -> str:
    conn = get_conn()
    cur = get_cursor(conn)
    token = str(uuid.uuid4())
    # store the uuid token in DB
    cur.execute(
        "INSERT INTO magic_tokens (user_id, token) VALUES (%s, %s) RETURNING token",
        (user_id, token),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row["token"]


def verify_magic_token(token: str) -> dict | None:
    conn = get_conn()
    cur = get_cursor(conn)
    cur.execute(
        """
        SELECT mt.*, u.email FROM magic_tokens mt
        JOIN users u ON u.id = mt.user_id
        WHERE mt.token = %s AND mt.used = FALSE AND mt.expires_at > NOW()
        """,
        (token,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None
    # Mark token as used
    cur.execute("UPDATE magic_tokens SET used = TRUE WHERE id = %s", (row["id"],))
    cur.close()
    conn.close()
    return dict(row)


def create_jwt(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
