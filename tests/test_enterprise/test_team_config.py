"""Tests for TeamConfigEnforcer: loading team config, merging with individual config, validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.core.config import DevNogConfig, ScanConfig
from devnog.core.models import Category, Finding, ScanReport, Severity
from devnog.enterprise.team_config import TeamConfig, TeamConfigEnforcer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_team_toml(project_path: Path, content: str) -> Path:
    """Write a devnog.team.toml file and return the path to it."""
    toml_file = project_path / "devnog.team.toml"
    toml_file.write_text(content)
    return toml_file


def _make_report(score: int, findings: list[Finding] | None = None) -> ScanReport:
    """Create a minimal ScanReport for testing."""
    return ScanReport(
        overall_score=score,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class TestTeamConfigEnforcerLoad:
    """Tests for TeamConfigEnforcer.load()."""

    def test_load_returns_none_when_no_file(self, tmp_path: Path):
        """When no devnog.team.toml exists, load() should return None."""
        enforcer = TeamConfigEnforcer(tmp_path)
        assert enforcer.load() is None

    def test_load_valid_toml_basic(self, tmp_path: Path):
        """Load a simple devnog.team.toml with team name and min_score."""
        _write_team_toml(tmp_path, """
[team]
name = "backend-squad"
min_score = 70
required_categories = ["security", "error_handling"]
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.name == "backend-squad"
        assert cfg.min_score == 70
        assert cfg.required_categories == ["security", "error_handling"]

    def test_load_scan_section(self, tmp_path: Path):
        """Load team scan settings (fail_under, ignore)."""
        _write_team_toml(tmp_path, """
[team]
name = "infra"

[team.scan]
fail_under = 80
ignore = ["QA-001", "QA-002"]
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.fail_under == 80
        assert cfg.team_ignores == ["QA-001", "QA-002"]

    def test_load_security_section(self, tmp_path: Path):
        """Load team security severity overrides."""
        _write_team_toml(tmp_path, """
[team]
name = "sec-team"

[team.security]
severity_overrides = {SEC-001 = "critical", SEC-002 = "warning"}
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.severity_overrides == {"SEC-001": "critical", "SEC-002": "warning"}

    def test_load_qa_section(self, tmp_path: Path):
        """Load team QA required checks."""
        _write_team_toml(tmp_path, """
[team]
name = "qa-team"

[team.qa]
required_checks = ["QA-010", "QA-022"]
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.required_checks == ["QA-010", "QA-022"]

    def test_load_full_config(self, tmp_path: Path):
        """Load a fully populated team config."""
        _write_team_toml(tmp_path, """
[team]
name = "platform"
min_score = 85
required_categories = ["security", "error_handling", "dependencies"]

[team.scan]
fail_under = 75
ignore = ["QA-003"]

[team.security]
severity_overrides = {SEC-005 = "critical"}

[team.qa]
required_checks = ["QA-010"]
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.name == "platform"
        assert cfg.min_score == 85
        assert cfg.required_categories == ["security", "error_handling", "dependencies"]
        assert cfg.fail_under == 75
        assert cfg.team_ignores == ["QA-003"]
        assert cfg.severity_overrides == {"SEC-005": "critical"}
        assert cfg.required_checks == ["QA-010"]

    def test_load_invalid_toml_returns_none(self, tmp_path: Path):
        """Malformed TOML should return None (not raise)."""
        _write_team_toml(tmp_path, "this is not valid [[[toml!!")
        enforcer = TeamConfigEnforcer(tmp_path)
        assert enforcer.load() is None

    def test_load_empty_toml_returns_defaults(self, tmp_path: Path):
        """An empty TOML file should return a TeamConfig with defaults."""
        _write_team_toml(tmp_path, "")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.name == ""
        assert cfg.min_score == 0
        assert cfg.required_categories == []
        assert cfg.fail_under == 0
        assert cfg.team_ignores == []

    def test_load_partial_config_fills_defaults(self, tmp_path: Path):
        """A TOML with only 'team.name' should leave other fields at defaults."""
        _write_team_toml(tmp_path, """
[team]
name = "core"
""")
        enforcer = TeamConfigEnforcer(tmp_path)
        cfg = enforcer.load()

        assert cfg is not None
        assert cfg.name == "core"
        assert cfg.min_score == 0
        assert cfg.required_categories == []
        assert cfg.fail_under == 0
        assert cfg.team_ignores == []
        assert cfg.severity_overrides == {}
        assert cfg.required_checks == []


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------

class TestTeamConfigEnforcerMerge:
    """Tests for TeamConfigEnforcer.merge() — team settings override individual."""

    def test_merge_fail_under_takes_max(self, tmp_path: Path):
        """Team fail_under should win when it is higher than individual."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(fail_under=80)
        individual = DevNogConfig(scan=ScanConfig(fail_under=50))

        merged = enforcer.merge(team, individual)
        assert merged.scan.fail_under == 80

    def test_merge_fail_under_keeps_individual_when_higher(self, tmp_path: Path):
        """If individual fail_under is higher, keep the individual value."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(fail_under=50)
        individual = DevNogConfig(scan=ScanConfig(fail_under=90))

        merged = enforcer.merge(team, individual)
        assert merged.scan.fail_under == 90

    def test_merge_fail_under_zero_team_no_override(self, tmp_path: Path):
        """Team fail_under=0 means no enforcement; individual value preserved."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(fail_under=0)
        individual = DevNogConfig(scan=ScanConfig(fail_under=60))

        merged = enforcer.merge(team, individual)
        assert merged.scan.fail_under == 60

    def test_merge_required_categories_added(self, tmp_path: Path):
        """Team required categories should be added to individual categories."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(required_categories=["security", "dependencies"])
        individual = DevNogConfig(
            scan=ScanConfig(categories=["code_quality", "security"])
        )

        merged = enforcer.merge(team, individual)
        assert "security" in merged.scan.categories
        assert "dependencies" in merged.scan.categories
        assert "code_quality" in merged.scan.categories
        # security should not be duplicated
        assert merged.scan.categories.count("security") == 1

    def test_merge_required_categories_empty_team(self, tmp_path: Path):
        """Empty team required_categories should not change individual categories."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(required_categories=[])
        individual = DevNogConfig(
            scan=ScanConfig(categories=["code_quality"])
        )

        merged = enforcer.merge(team, individual)
        assert merged.scan.categories == ["code_quality"]

    def test_merge_team_ignores_remove_from_individual(self, tmp_path: Path):
        """Team ignores should be removed from individual ignore list."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(team_ignores=["QA-001", "QA-003"])
        individual = DevNogConfig(
            scan=ScanConfig(ignore=["QA-001", "QA-002", "QA-003", "QA-004"])
        )

        merged = enforcer.merge(team, individual)
        assert merged.scan.ignore == ["QA-002", "QA-004"]

    def test_merge_team_ignores_no_match(self, tmp_path: Path):
        """When team ignores don't match individual ignores, list unchanged."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(team_ignores=["SEC-999"])
        individual = DevNogConfig(
            scan=ScanConfig(ignore=["QA-001", "QA-002"])
        )

        merged = enforcer.merge(team, individual)
        assert merged.scan.ignore == ["QA-001", "QA-002"]

    def test_merge_combined_effects(self, tmp_path: Path):
        """All merge operations should be applied together."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(
            fail_under=70,
            required_categories=["security"],
            team_ignores=["QA-001"],
        )
        individual = DevNogConfig(
            scan=ScanConfig(
                fail_under=50,
                categories=["code_quality"],
                ignore=["QA-001", "SEC-002"],
            )
        )

        merged = enforcer.merge(team, individual)
        assert merged.scan.fail_under == 70
        assert "security" in merged.scan.categories
        assert "code_quality" in merged.scan.categories
        assert merged.scan.ignore == ["SEC-002"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestTeamConfigEnforcerValidate:
    """Tests for TeamConfigEnforcer.validate_scan()."""

    def test_validate_passes_above_min_score(self, tmp_path: Path):
        """Scan should pass when score meets min_score."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=70)
        report = _make_report(score=85)

        assert enforcer.validate_scan(report, team) is True

    def test_validate_passes_exactly_at_min_score(self, tmp_path: Path):
        """Scan should pass when score exactly equals min_score."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=70)
        report = _make_report(score=70)

        assert enforcer.validate_scan(report, team) is True

    def test_validate_fails_below_min_score(self, tmp_path: Path):
        """Scan should fail when score is below min_score."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=70)
        report = _make_report(score=65)

        assert enforcer.validate_scan(report, team) is False

    def test_validate_fails_below_fail_under(self, tmp_path: Path):
        """Scan should fail when score is below fail_under."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(fail_under=80)
        report = _make_report(score=75)

        assert enforcer.validate_scan(report, team) is False

    def test_validate_passes_above_fail_under(self, tmp_path: Path):
        """Scan should pass when score meets fail_under."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(fail_under=80)
        report = _make_report(score=85)

        assert enforcer.validate_scan(report, team) is True

    def test_validate_both_thresholds_strictest_wins(self, tmp_path: Path):
        """When both min_score and fail_under are set, both must be met."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=70, fail_under=80)
        # Score between min_score and fail_under -> fails fail_under
        report = _make_report(score=75)

        assert enforcer.validate_scan(report, team) is False

    def test_validate_no_thresholds_always_passes(self, tmp_path: Path):
        """With min_score=0 and fail_under=0, any score should pass."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=0, fail_under=0)
        report = _make_report(score=10)

        assert enforcer.validate_scan(report, team) is True

    def test_validate_zero_score_fails_nonzero_threshold(self, tmp_path: Path):
        """A score of 0 should fail any nonzero threshold."""
        enforcer = TeamConfigEnforcer(tmp_path)
        team = TeamConfig(min_score=1)
        report = _make_report(score=0)

        assert enforcer.validate_scan(report, team) is False
