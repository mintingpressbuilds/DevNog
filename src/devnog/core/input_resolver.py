"""Resolves scan target: directory, .zip, or GitHub URL."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ResolvedInput:
    """Result of resolving a scan target to a local directory path."""

    path: Path
    is_temp: bool
    source_type: str  # "directory", "zip", "github"
    original_target: str


class InputResolver:
    """Resolves scan target to a local directory path."""

    MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB

    async def resolve(self, target: str) -> ResolvedInput:
        """
        Accepts:
        1. Directory path -> use directly
        2. Zip file path -> extract to temp
        3. GitHub URL -> shallow clone to temp
        """
        if self._is_github_url(target):
            return await self._resolve_github(target)

        path = Path(target).resolve()

        if path.is_file() and path.suffix == ".zip":
            return await self._resolve_zip(path)

        if path.is_dir():
            return ResolvedInput(
                path=path,
                is_temp=False,
                source_type="directory",
                original_target=target,
            )

        raise ValueError(
            f"Invalid scan target: '{target}'. "
            "Expected a directory path, .zip file, or GitHub URL."
        )

    async def cleanup(self, resolved: ResolvedInput) -> None:
        """Delete temp directory if is_temp=True."""
        if resolved.is_temp and resolved.path.exists():
            shutil.rmtree(resolved.path, ignore_errors=True)

    def _is_github_url(self, target: str) -> bool:
        """Check if target looks like a GitHub URL."""
        return bool(
            re.match(r"https?://(www\.)?github\.com/[\w\-]+/[\w\-]+", target)
        )

    async def _resolve_zip(self, zip_path: Path) -> ResolvedInput:
        """Extract zip to temp directory with ZipSlip protection."""
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")

        if zip_path.stat().st_size > self.MAX_ZIP_SIZE:
            raise ValueError(
                f"Zip file too large ({zip_path.stat().st_size / 1024 / 1024:.0f}MB). "
                f"Maximum size: {self.MAX_ZIP_SIZE / 1024 / 1024:.0f}MB."
            )

        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"Not a valid zip file: {zip_path}")

        temp_dir = Path(tempfile.mkdtemp(prefix="devnog_"))

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # ZipSlip protection: validate all paths
                for member in zf.namelist():
                    member_path = (temp_dir / member).resolve()
                    if not str(member_path).startswith(str(temp_dir)):
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        raise ValueError(
                            f"Zip file contains unsafe path: {member}. "
                            "Possible ZipSlip attack."
                        )

                zf.extractall(temp_dir)

            # If zip contains a single top-level directory, use that
            contents = list(temp_dir.iterdir())
            if len(contents) == 1 and contents[0].is_dir():
                return ResolvedInput(
                    path=contents[0],
                    is_temp=True,
                    source_type="zip",
                    original_target=str(zip_path),
                )

            return ResolvedInput(
                path=temp_dir,
                is_temp=True,
                source_type="zip",
                original_target=str(zip_path),
            )
        except (zipfile.BadZipFile, ValueError):
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    async def _resolve_github(self, url: str) -> ResolvedInput:
        """Shallow clone a GitHub repo to temp directory."""
        if not shutil.which("git"):
            raise EnvironmentError(
                "Git is required to scan GitHub repos. Install git or download "
                "the repo as a zip and use: devnog scan repo.zip"
            )

        temp_dir = Path(tempfile.mkdtemp(prefix="devnog_"))

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", url, str(temp_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise ValueError(
                    f"Failed to clone {url}: {result.stderr.strip()}\n"
                    "Make sure the URL is correct and the repo is public."
                )

            return ResolvedInput(
                path=temp_dir,
                is_temp=True,
                source_type="github",
                original_target=url,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ValueError(
                f"Git clone timed out for {url}. "
                "Try downloading as a zip instead."
            )
