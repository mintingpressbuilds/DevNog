"""Enforced team configuration via devnog.team.toml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devnog.core.config import DevNogConfig
from devnog.core.models import ScanReport


@dataclass
class TeamConfig:
    """Team-enforced configuration from devnog.team.toml."""

    name: str = ""
    min_score: int = 0
    required_categories: list[str] = field(default_factory=list)
    fail_under: int = 0
    team_ignores: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    required_checks: list[str] = field(default_factory=list)


class TeamConfigEnforcer:
    """Loads and enforces devnog.team.toml settings."""

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def load(self) -> TeamConfig | None:
        """Load team config if present. Returns None if not found."""
        config_file = self.project_path / "devnog.team.toml"
        if not config_file.exists():
            return None

        try:
            try:
                import tomllib
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError:
                    return None

            with open(config_file, "rb") as f:
                data = tomllib.load(f)

            team_data = data.get("team", {})
            config = TeamConfig(
                name=team_data.get("name", ""),
                min_score=team_data.get("min_score", 0),
                required_categories=team_data.get("required_categories", []),
            )

            scan_data = team_data.get("scan", data.get("team.scan", {}))
            config.fail_under = scan_data.get("fail_under", 0)
            config.team_ignores = scan_data.get("ignore", [])

            security_data = team_data.get("security", data.get("team.security", {}))
            config.severity_overrides = security_data.get("severity_overrides", {})

            qa_data = team_data.get("qa", data.get("team.qa", {}))
            config.required_checks = qa_data.get("required_checks", [])

            return config
        except Exception:
            return None

    def merge(self, team: TeamConfig, individual: DevNogConfig) -> DevNogConfig:
        """Merge configs. Team settings override individual settings."""
        if team.fail_under:
            individual.scan.fail_under = max(individual.scan.fail_under, team.fail_under)

        if team.required_categories:
            # Ensure required categories are always included
            for cat in team.required_categories:
                if cat not in individual.scan.categories:
                    individual.scan.categories.append(cat)

        # Team ignores override: remove individual ignores that team requires
        if team.team_ignores:
            individual.scan.ignore = [
                i for i in individual.scan.ignore if i not in team.team_ignores
            ]

        return individual

    def validate_scan(self, report: ScanReport, team: TeamConfig) -> bool:
        """Check if scan results meet team requirements."""
        if team.min_score and report.overall_score < team.min_score:
            return False

        if team.fail_under and report.overall_score < team.fail_under:
            return False

        return True
