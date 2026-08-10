"""S01: build a minimal npm SBOM from a local project manifest and lockfile."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from supplyguard.models.messages import DependencyChange


class SbomBuildInput(BaseModel):
    """A local npm project to inspect."""

    repo_path: str
    include_dev_dependencies: bool = False


class SbomBuildOutput(BaseModel):
    """A partial SBOM suitable for the Analyst workflow."""

    repo_path: str
    manifest_path: str
    lockfile_path: str | None = None
    dependencies: list[DependencyChange] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SbomBuildSkill:
    """Parse direct npm dependencies without running package-manager scripts."""

    name = "sbom-build"
    description = "Build a direct-dependency SBOM from package.json and package-lock.json"

    def run(self, input_data: SbomBuildInput) -> SbomBuildOutput:
        """Return declared dependencies with resolved versions when available."""
        repo_path = Path(input_data.repo_path).expanduser().resolve()
        manifest_path = repo_path / "package.json"
        if not manifest_path.is_file():
            msg = f"No package.json found in {repo_path}"
            raise ValueError(msg)

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            msg = f"Invalid package.json: {exc.msg}"
            raise ValueError(msg) from exc

        declared = dict(manifest.get("dependencies", {}))
        if input_data.include_dev_dependencies:
            declared.update(manifest.get("devDependencies", {}))

        lockfile_path = repo_path / "package-lock.json"
        lock_data: dict[str, Any] = {}
        warnings: list[str] = []
        if lockfile_path.is_file():
            try:
                lock_data = json.loads(lockfile_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                warnings.append("package-lock.json is invalid; using declared versions only.")
        else:
            warnings.append("package-lock.json not found; using declared versions only.")

        dependencies = [
            DependencyChange(
                package_name=name,
                old_version=self._locked_version(lock_data, name),
                new_version=str(version),
                is_new=self._locked_version(lock_data, name) is None,
                ecosystem="npm",
                context_text=(
                    f"Dependency discovered in package.json: {name}; "
                    f"declared={version}; locked={self._locked_version(lock_data, name) or 'unresolved'}"
                ),
            )
            for name, version in sorted(declared.items())
        ]

        return SbomBuildOutput(
            repo_path=str(repo_path),
            manifest_path=str(manifest_path),
            lockfile_path=str(lockfile_path) if lockfile_path.is_file() else None,
            dependencies=dependencies,
            warnings=warnings,
        )

    @staticmethod
    def _locked_version(lock_data: dict[str, Any], package_name: str) -> str | None:
        """Read a direct package version from npm lockfile v1, v2, or v3."""
        packages = lock_data.get("packages", {})
        package_info = packages.get(f"node_modules/{package_name}", {})
        if isinstance(package_info, dict) and isinstance(package_info.get("version"), str):
            return package_info["version"]

        dependency_info = lock_data.get("dependencies", {}).get(package_name, {})
        if isinstance(dependency_info, dict) and isinstance(dependency_info.get("version"), str):
            return dependency_info["version"]
        return None
