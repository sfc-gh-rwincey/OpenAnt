#!/usr/bin/env python3
"""
CI/CD Workflow Parser

Parses CI/CD configuration files into structured representations,
extracting security-relevant metadata for each workflow/pipeline.

Supported platforms:
- GitHub Actions (primary, most detailed)
- GitLab CI (basic)
- Jenkinsfile (basic)

This is Phase 2 of the CI/CD parser — structural extraction.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class WorkflowParser:
    """Parse CI/CD config files into structured workflow representations."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()

    def parse_file(self, rel_path: str, platform: str) -> Optional[dict]:
        """Parse a single CI/CD config file.

        Args:
            rel_path: Path relative to repo root.
            platform: CI/CD platform identifier.

        Returns:
            Parsed workflow dict, or None on parse error.
        """
        abs_path = self.repo_path / rel_path
        if not abs_path.is_file():
            return None

        raw_content = abs_path.read_text(encoding="utf-8", errors="replace")

        if platform == "github_actions":
            return self._parse_github_actions(rel_path, raw_content)
        elif platform == "gitlab_ci":
            return self._parse_gitlab_ci(rel_path, raw_content)
        elif platform == "jenkins":
            return self._parse_jenkins(rel_path, raw_content)
        else:
            return self._parse_generic_yaml(rel_path, raw_content, platform)

    # ------------------------------------------------------------------
    # GitHub Actions
    # ------------------------------------------------------------------

    def _parse_github_actions(self, rel_path: str, raw: str) -> Optional[dict]:
        """Parse a GitHub Actions workflow YAML."""
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

        if not isinstance(data, dict):
            return None

        workflow_name = data.get("name", Path(rel_path).stem)

        # Extract triggers — YAML parses 'on' as boolean True
        on_block = data.get("on") or data.get(True, {})

        triggers = self._extract_gha_triggers(on_block)

        # Workflow-level env and permissions
        workflow_env = data.get("env", {})
        workflow_permissions = data.get("permissions", None)

        # Extract jobs
        jobs = {}
        for job_id, job_def in (data.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            jobs[job_id] = self._extract_gha_job(job_id, job_def)

        return {
            "file_path": rel_path,
            "platform": "github_actions",
            "name": workflow_name,
            "raw_content": raw,
            "triggers": triggers,
            "workflow_env": workflow_env,
            "workflow_permissions": workflow_permissions,
            "jobs": jobs,
            "concurrency": data.get("concurrency"),
            "defaults": data.get("defaults"),
        }

    def _extract_gha_triggers(self, on_block) -> list[dict]:
        """Extract trigger definitions from the 'on:' block."""
        triggers = []

        if isinstance(on_block, str):
            triggers.append({"event": on_block})
        elif isinstance(on_block, list):
            for event in on_block:
                triggers.append({"event": event})
        elif isinstance(on_block, dict):
            for event, config in on_block.items():
                trigger = {"event": event}
                if isinstance(config, dict):
                    trigger["branches"] = config.get("branches", [])
                    trigger["branches-ignore"] = config.get("branches-ignore", [])
                    trigger["paths"] = config.get("paths", [])
                    trigger["types"] = config.get("types", [])
                    if event == "workflow_dispatch":
                        trigger["inputs"] = config.get("inputs", {})
                    if event == "workflow_call":
                        trigger["inputs"] = config.get("inputs", {})
                        trigger["secrets"] = config.get("secrets", {})
                triggers.append(trigger)

        return triggers

    def _extract_gha_job(self, job_id: str, job_def: dict) -> dict:
        """Extract a single GitHub Actions job definition."""
        steps = []
        for i, step_def in enumerate(job_def.get("steps") or []):
            if not isinstance(step_def, dict):
                continue
            step = {
                "index": i,
                "name": step_def.get("name", f"step_{i}"),
                "uses": step_def.get("uses"),
                "run": step_def.get("run"),
                "with": step_def.get("with", {}),
                "env": step_def.get("env", {}),
                "if": step_def.get("if"),
            }
            steps.append(step)

        return {
            "job_id": job_id,
            "name": job_def.get("name", job_id),
            "runs_on": job_def.get("runs-on"),
            "environment": job_def.get("environment"),
            "permissions": job_def.get("permissions"),
            "needs": job_def.get("needs", []),
            "if": job_def.get("if"),
            "env": job_def.get("env", {}),
            "steps": steps,
            "strategy": job_def.get("strategy"),
            "services": job_def.get("services"),
            "container": job_def.get("container"),
            "concurrency": job_def.get("concurrency"),
            "outputs": job_def.get("outputs"),
        }

    # ------------------------------------------------------------------
    # GitLab CI
    # ------------------------------------------------------------------

    def _parse_gitlab_ci(self, rel_path: str, raw: str) -> Optional[dict]:
        """Parse a GitLab CI YAML (basic extraction)."""
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

        if not isinstance(data, dict):
            return None

        # GitLab CI jobs are top-level keys that aren't reserved keywords
        reserved = {
            "image", "services", "before_script", "after_script",
            "variables", "stages", "cache", "include", "default",
            "workflow", "pages",
        }

        jobs = {}
        for key, val in data.items():
            if key.startswith(".") or key in reserved:
                continue
            if isinstance(val, dict) and ("script" in val or "stage" in val):
                jobs[key] = {
                    "job_id": key,
                    "name": key,
                    "stage": val.get("stage"),
                    "script": val.get("script", []),
                    "variables": val.get("variables", {}),
                    "environment": val.get("environment"),
                    "rules": val.get("rules", []),
                    "only": val.get("only"),
                    "except": val.get("except"),
                }

        return {
            "file_path": rel_path,
            "platform": "gitlab_ci",
            "name": Path(rel_path).stem,
            "raw_content": raw,
            "triggers": [],  # GitLab triggers are more implicit
            "workflow_env": data.get("variables", {}),
            "workflow_permissions": None,
            "jobs": jobs,
        }

    # ------------------------------------------------------------------
    # Jenkins
    # ------------------------------------------------------------------

    def _parse_jenkins(self, rel_path: str, raw: str) -> Optional[dict]:
        """Parse a Jenkinsfile (basic — returns raw content for LLM analysis)."""
        # Jenkinsfiles are Groovy, not YAML. We extract what we can with regex
        # but primarily rely on the LLM for deep analysis.

        stages = []
        for m in re.finditer(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", raw):
            stages.append(m.group(1))

        # Detect credential usage
        credentials_refs = list(set(re.findall(
            r"credentials\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", raw
        )))

        # Detect environment blocks
        env_blocks = re.findall(r"environment\s*\{([^}]+)\}", raw, re.DOTALL)

        return {
            "file_path": rel_path,
            "platform": "jenkins",
            "name": Path(rel_path).stem,
            "raw_content": raw,
            "triggers": [],
            "workflow_env": {},
            "workflow_permissions": None,
            "jobs": {f"stage_{i}": {"job_id": s, "name": s} for i, s in enumerate(stages)},
            "jenkins_metadata": {
                "stages": stages,
                "credentials_refs": credentials_refs,
                "env_blocks": env_blocks,
            },
        }

    # ------------------------------------------------------------------
    # Generic YAML
    # ------------------------------------------------------------------

    def _parse_generic_yaml(self, rel_path: str, raw: str, platform: str) -> Optional[dict]:
        """Fallback parser for other YAML-based CI configs."""
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

        return {
            "file_path": rel_path,
            "platform": platform,
            "name": Path(rel_path).stem,
            "raw_content": raw,
            "triggers": [],
            "workflow_env": {},
            "workflow_permissions": None,
            "jobs": {},
            "parsed_data": data if isinstance(data, dict) else {},
        }
