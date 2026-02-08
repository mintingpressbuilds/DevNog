"""Fernet encryption for capture storage."""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet


def get_or_create_key(devnog_dir: Path) -> bytes:
    """Get existing Fernet key or create a new one."""
    key_file = devnog_dir / "key"
    if key_file.exists():
        return key_file.read_bytes().strip()

    key = Fernet.generate_key()
    devnog_dir.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return key


def get_fernet(devnog_dir: Path) -> Fernet:
    """Get a Fernet instance with the project's encryption key."""
    key = get_or_create_key(devnog_dir)
    return Fernet(key)


def encrypt_data(data: bytes, devnog_dir: Path) -> bytes:
    """Encrypt data using project Fernet key."""
    f = get_fernet(devnog_dir)
    return f.encrypt(data)


def decrypt_data(token: bytes, devnog_dir: Path) -> bytes:
    """Decrypt data using project Fernet key."""
    f = get_fernet(devnog_dir)
    return f.decrypt(token)
