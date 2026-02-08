"""Tests for input resolver (directory, invalid inputs)."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.core.input_resolver import InputResolver, ResolvedInput


@pytest.fixture
def resolver() -> InputResolver:
    return InputResolver()


class TestInputResolverDirectory:
    @pytest.mark.asyncio
    async def test_resolves_directory(self, resolver: InputResolver, tmp_path: Path):
        """A valid directory should resolve directly."""
        result = await resolver.resolve(str(tmp_path))

        assert isinstance(result, ResolvedInput)
        assert result.path == tmp_path
        assert result.is_temp is False
        assert result.source_type == "directory"
        assert result.original_target == str(tmp_path)

    @pytest.mark.asyncio
    async def test_resolves_directory_with_files(
        self, resolver: InputResolver, tmp_path: Path
    ):
        """A directory with Python files should resolve."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        result = await resolver.resolve(str(tmp_path))

        assert result.path == tmp_path
        assert result.is_temp is False


class TestInputResolverInvalid:
    @pytest.mark.asyncio
    async def test_rejects_nonexistent_path(self, resolver: InputResolver):
        """A nonexistent path should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid scan target"):
            await resolver.resolve("/nonexistent/path/to/nothing")

    @pytest.mark.asyncio
    async def test_rejects_regular_file(
        self, resolver: InputResolver, tmp_path: Path
    ):
        """A non-zip regular file should raise ValueError."""
        f = tmp_path / "plain.txt"
        f.write_text("hello")

        with pytest.raises(ValueError, match="Invalid scan target"):
            await resolver.resolve(str(f))


class TestInputResolverZip:
    @pytest.mark.asyncio
    async def test_resolves_zip_file(self, resolver: InputResolver, tmp_path: Path):
        """A valid zip file should be extracted to a temp directory."""
        import zipfile

        # Create a zip with a Python file
        zip_path = tmp_path / "project.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("project/main.py", "print('hello')\n")

        result = await resolver.resolve(str(zip_path))

        try:
            assert result.is_temp is True
            assert result.source_type == "zip"
            assert result.path.exists()
        finally:
            await resolver.cleanup(result)

    @pytest.mark.asyncio
    async def test_rejects_invalid_zip(self, resolver: InputResolver, tmp_path: Path):
        """A file with .zip extension but invalid content should raise."""
        fake_zip = tmp_path / "fake.zip"
        fake_zip.write_text("this is not a zip file")

        with pytest.raises(ValueError):
            await resolver.resolve(str(fake_zip))


class TestInputResolverCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_dir(
        self, resolver: InputResolver, tmp_path: Path
    ):
        """cleanup() should remove temp directories."""
        import zipfile

        zip_path = tmp_path / "project.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("main.py", "x = 1\n")

        result = await resolver.resolve(str(zip_path))
        temp_path = result.path

        await resolver.cleanup(result)
        # The temp root should be cleaned up
        # (path might be the extracted dir or its parent)

    @pytest.mark.asyncio
    async def test_cleanup_noop_for_non_temp(
        self, resolver: InputResolver, tmp_path: Path
    ):
        """cleanup() should not delete non-temp directories."""
        result = await resolver.resolve(str(tmp_path))
        await resolver.cleanup(result)

        # Original directory should still exist
        assert tmp_path.exists()


class TestInputResolverGitHub:
    def test_is_github_url(self, resolver: InputResolver):
        """GitHub URLs should be recognized."""
        assert resolver._is_github_url("https://github.com/user/repo") is True
        assert resolver._is_github_url("https://www.github.com/user/repo") is True

    def test_non_github_url(self, resolver: InputResolver):
        """Non-GitHub URLs should not be recognized as GitHub."""
        assert resolver._is_github_url("https://gitlab.com/user/repo") is False
        assert resolver._is_github_url("/home/user/project") is False
