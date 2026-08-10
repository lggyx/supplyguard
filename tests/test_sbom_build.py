"""Tests for local npm SBOM construction."""

from __future__ import annotations

import json
from pathlib import Path

from supplyguard.skills.sbom_build import SbomBuildInput, SbomBuildSkill


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_builds_sbom_from_manifest_and_npm_v3_lockfile(tmp_path: Path) -> None:
    write_json(
        tmp_path / "package.json",
        {
            "dependencies": {"express": "^4.16.0", "lodash": "^4.17.4"},
            "devDependencies": {"jest": "^29.0.0"},
        },
    )
    write_json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/express": {"version": "4.16.0"},
                "node_modules/lodash": {"version": "4.17.4"},
            },
        },
    )

    result = SbomBuildSkill().run(SbomBuildInput(repo_path=str(tmp_path)))

    assert [change.package_name for change in result.dependencies] == ["express", "lodash"]
    assert result.dependencies[0].old_version == "4.16.0"
    assert result.dependencies[1].old_version == "4.17.4"
    assert result.warnings == []


def test_reports_a_missing_lockfile_without_losing_manifest_dependencies(tmp_path: Path) -> None:
    write_json(tmp_path / "package.json", {"dependencies": {"lodash": "^4.17.4"}})

    result = SbomBuildSkill().run(SbomBuildInput(repo_path=str(tmp_path)))

    assert result.dependencies[0].package_name == "lodash"
    assert result.dependencies[0].is_new is True
    assert result.warnings == ["package-lock.json not found; using declared versions only."]
