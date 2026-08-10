"""Sentinel agent: entry point and coordinator."""

from __future__ import annotations

from typing import ClassVar

from supplyguard.models.messages import (
    AnalysisRequest,
    DependencyChange,
    EventSource,
)
from supplyguard.skills.sbom_build import SbomBuildInput, SbomBuildSkill

from .base import Agent


class SentinelAgent(Agent):
    """Listens to external events and routes tasks to Analyst."""

    name = "Sentinel"
    role = "coordinator"
    skills: ClassVar[list[str]] = ["policy-check"]

    def __init__(self, runtime: object | None = None) -> None:
        super().__init__(runtime)
        self.sbom_build_skill = SbomBuildSkill()

    async def handle(self, message: object) -> AnalysisRequest | None:
        """Transform external event into an AnalysisRequest.

        This is the "perception layer" of the onion architecture:
        all inputs are tagged as UNTRUSTED and wrapped with boundaries.
        """
        if isinstance(message, AnalysisRequest):
            return message

        # Demo helper: accept raw dicts for convenience.
        if isinstance(message, dict):
            repo = message.get("repo_url", "")
            commit = message.get("commit_sha", "")
            changes_raw = message.get("changes", [])
            repo_path = message.get("repo_path")
            if not changes_raw and repo_path:
                sbom = self.sbom_build_skill.run(
                    SbomBuildInput(
                        repo_path=str(repo_path),
                        include_dev_dependencies=bool(
                            message.get("include_dev_dependencies", False)
                        ),
                    )
                )
                changes_raw = [change.model_dump() for change in sbom.dependencies]
            source = EventSource(message.get("source", "manual"))
            changes = []
            for raw_change in changes_raw:
                change = dict(raw_change)
                context = change.get("context_text", "")
                if not context.startswith("<untrusted_source>"):
                    change["context_text"] = self.tag_untrusted(context)
                changes.append(DependencyChange(**change))
            return AnalysisRequest(
                session_id=message.get("session_id", "demo-session"),
                source=source,
                repo_url=repo,
                commit_sha=commit,
                changes=changes,
            )

        return None

    def tag_untrusted(self, text: str) -> str:
        """Wrap raw external text with boundary markers."""
        return f"<untrusted_source>\n{text}\n</untrusted_source>"
