"""Sample API client with intentional issues for DevNog demo.

Issues present:
- ERR-007: HTTP calls without timeout
- SEC-004: eval() usage
- ERR-004: API calls without error handling (no try/except)
"""

import requests


def fetch_users():
    """Fetch users from API -- no timeout, no error handling."""
    # ERR-007: HTTP call without timeout
    # ERR-004: API call without error handling
    response = requests.get("https://api.example.com/users")
    return response.json()


def fetch_user_by_id(user_id):
    """Fetch a single user -- no timeout."""
    # ERR-007: HTTP call without timeout
    # ERR-004: API call without error handling
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()


def create_user(data):
    """Create user via POST -- no timeout."""
    # ERR-007: HTTP call without timeout
    # ERR-004: API call without error handling
    response = requests.post("https://api.example.com/users", json=data)
    return response.json()


def update_user(user_id, data):
    """Update user via PUT -- no timeout."""
    # ERR-007: HTTP call without timeout
    response = requests.put(f"https://api.example.com/users/{user_id}", json=data)
    return response.json()


def parse_dynamic_config(config_string):
    """Parse config using eval -- dangerous!"""
    # SEC-004: eval() can execute arbitrary code
    config = eval(config_string)
    return config


def execute_dynamic_code(code_string):
    """Execute dynamic code -- dangerous!"""
    # SEC-004: exec() can execute arbitrary code
    exec(code_string)
