"""Sample configuration file with intentional issues for DevNog demo.

Issues present:
- SEC-001: Hardcoded secrets (API keys, passwords)
- SEC-006: DEBUG = True
"""

# SEC-006: DEBUG = True in production-accessible code
DEBUG = True

# SEC-001: Hardcoded secrets
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
SECRET_KEY = "super-secret-key-do-not-share-with-anyone"
DATABASE_URL = "postgresql://admin:p4ssw0rd@db.example.com:5432/myapp"
password = "hunter2"
api_secret = "a1b2c3d4e5f6g7h8i9j0"

# Also bad: AWS-style key
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"

# This is fine (reading from env)
import os

SAFE_KEY = os.environ.get("API_KEY", "")

# Application settings
APP_NAME = "MyApp"
MAX_RETRIES = 3
TIMEOUT = 30
