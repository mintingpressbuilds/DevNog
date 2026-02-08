"""Sample database module with intentional issues for DevNog demo.

Issues present:
- SEC-002: SQL injection via f-string and .format()
- ERR-001: Bare except clause
- ERR-002: except: pass (silent exception)
"""

import sqlite3


def get_connection():
    """Get a database connection."""
    return sqlite3.connect("app.db")


def get_user_by_name(name):
    """Fetch user by name -- SQL injection via f-string."""
    conn = get_connection()
    # SEC-002: SQL injection risk -- f-string in SQL query
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor = conn.execute(query)
    return cursor.fetchone()


def get_user_by_email(email):
    """Fetch user by email -- SQL injection via .format()."""
    conn = get_connection()
    # SEC-002: SQL injection risk -- .format() in SQL query
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor = conn.execute(query)
    return cursor.fetchone()


def delete_user(user_id):
    """Delete user -- SQL injection via % formatting."""
    conn = get_connection()
    # SEC-002: SQL injection risk -- % formatting in SQL query
    query = "DELETE FROM users WHERE id = %s" % user_id
    conn.execute(query)
    conn.commit()


def save_user(name, email):
    """Save a user with error handling issues."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            (name, email),
        )
        conn.commit()
    # ERR-001: Bare except clause
    except:
        conn.rollback()


def load_settings():
    """Load settings with silent exception."""
    try:
        with open("settings.json") as f:
            import json
            return json.load(f)
    # ERR-002: except: pass -- silently swallows all errors
    except:
        pass


def update_user_score(user_id, score):
    """Another bare except example."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET score = ? WHERE id = ?",
            (score, user_id),
        )
        conn.commit()
    # ERR-001 + ERR-002: bare except with pass
    except:
        pass
