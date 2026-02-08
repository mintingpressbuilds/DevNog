"""Sample security module with intentional issues for DevNog demo.

Issues present:
- SEC-009: Weak hashing (MD5)
- SEC-012: subprocess with shell=True
- SEC-005: Open CORS configuration
"""

import hashlib
import subprocess


def hash_password(password):
    """Hash a password using MD5 -- weak!"""
    # SEC-009: Weak hash algorithm -- MD5
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    """Hash a token using SHA1 -- weak!"""
    # SEC-009: Weak hash algorithm -- SHA1
    return hashlib.sha1(token.encode()).hexdigest()


def run_command(cmd):
    """Run a shell command -- dangerous!"""
    # SEC-012: subprocess with shell=True -- command injection risk
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def run_system_command(cmd):
    """Run a command via os.system -- dangerous!"""
    import os
    # SEC-012: os.system() -- command injection risk
    os.system(cmd)


def configure_cors(app):
    """Configure CORS with wildcard -- too permissive."""
    # SEC-005: Open CORS -- allows all origins
    app.add_middleware(
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


def hash_with_new(data):
    """Hash using hashlib.new('md5') -- weak!"""
    # SEC-009: Weak hash via hashlib.new()
    return hashlib.new("md5", data.encode()).hexdigest()
