"""Scan direct npm dependencies in a local project through SupplyGuard."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(project_root / "src"))

from supplyguard.runtime.local_orchestrator import LocalOrchestrator


async def main(repo_path: str, include_dev_dependencies: bool) -> None:
    """Build an SBOM and assess each direct npm dependency."""
    resolved_path = Path(repo_path).resolve()
    orchestrator = LocalOrchestrator()
    try:
        result = await orchestrator.run_guard(
            {
                "session_id": "local-repository-scan",
                "source": "manual",
                "repo_url": resolved_path.as_uri(),
                "repo_path": str(resolved_path),
                "include_dev_dependencies": include_dev_dependencies,
                "commit_sha": "local-working-tree",
                "changes": [],
            }
        )
    finally:
        await orchestrator.close()

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a local npm project's direct dependencies.")
    parser.add_argument("repo_path", help="Directory containing package.json")
    parser.add_argument("--include-dev", action="store_true", help="Include devDependencies")
    arguments = parser.parse_args()
    asyncio.run(main(arguments.repo_path, arguments.include_dev))
