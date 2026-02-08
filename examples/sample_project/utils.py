"""Sample utility module with intentional issues for DevNog demo.

Issues present:
- CQ-004: Unused imports
- CQ-009: Star imports (from os.path import *)
- CQ-010: Dead code (unreachable code after return)
- CQ-001: Long function (>50 lines)
"""

# CQ-004: Unused imports
import sys
import json
import re
import math

# CQ-009: Star import
from os.path import *


def format_name(first, last):
    """Format a full name."""
    return f"{first} {last}"


def dead_code_example():
    """Function with unreachable code after return."""
    result = 42
    return result
    # CQ-010: Dead code -- unreachable after return
    print("This will never execute")
    result = result + 1


def another_dead_code():
    """Function with dead code after raise."""
    raise ValueError("always fails")
    # CQ-010: Dead code -- unreachable after raise
    return "never reached"


def process_data_long_function(data):
    """A function that is way too long (>50 lines).

    CQ-001: Function too long.
    """
    # Step 1: Validate input
    if data is None:
        return None
    if not isinstance(data, dict):
        return None

    # Step 2: Extract fields
    name = data.get("name", "")
    email = data.get("email", "")
    age = data.get("age", 0)
    address = data.get("address", "")
    phone = data.get("phone", "")
    country = data.get("country", "")

    # Step 3: Validate fields
    if not name:
        return {"error": "name is required"}
    if not email:
        return {"error": "email is required"}
    if age < 0:
        return {"error": "age must be positive"}
    if age > 150:
        return {"error": "age seems invalid"}

    # Step 4: Normalize
    name = name.strip().title()
    email = email.strip().lower()
    address = address.strip()
    phone = phone.strip()
    country = country.strip().upper()

    # Step 5: Build result
    result = {
        "name": name,
        "email": email,
        "age": age,
        "address": address,
        "phone": phone,
        "country": country,
    }

    # Step 6: Add metadata
    result["processed"] = True
    result["version"] = "1.0"

    # Step 7: Additional processing
    if country == "US":
        result["region"] = "North America"
    elif country == "CA":
        result["region"] = "North America"
    elif country == "MX":
        result["region"] = "North America"
    elif country == "GB":
        result["region"] = "Europe"
    elif country == "FR":
        result["region"] = "Europe"
    elif country == "DE":
        result["region"] = "Europe"
    elif country == "JP":
        result["region"] = "Asia"
    elif country == "CN":
        result["region"] = "Asia"
    elif country == "KR":
        result["region"] = "Asia"
    elif country == "AU":
        result["region"] = "Oceania"
    else:
        result["region"] = "Other"

    # Step 8: Format output
    result["display_name"] = f"{name} ({email})"

    # Step 9: Return
    return result
