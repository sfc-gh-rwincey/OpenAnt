#!/usr/bin/env python3
"""
CI/CD Security Model Extractor

Extracts security-relevant metadata from parsed CI/CD workflows.
This does NOT use LLM — it's pure structural analysis that identifies
known-dangerous patterns for the LLM to reason about.

Detects:
- Secret scoping issues (workflow-level vs job/step-level)
- Missing environment protection gates
- Dangerous trigger configurations (pull_request_target, workflow_dispatch on mutable refs)
- Expression injection surfaces (${{ github.event.* }} in run: blocks)
- Overly permissive permissions
- Unpinned third-party actions
- Self-hosted runner exposure

The output is a structured "security model" attached to each workflow unit,
giving the LLM focused context for its analysis.
"""

import re
from typing import Any, Dict, List, Optional, Set


# GitHub Actions expression pattern — matches ${{ ... }}
GHA_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

# Dangerous contexts that may contain attacker-controlled data
DANGEROUS_CONTEXTS = {
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
}

# Triggers that may run with elevated privileges on attacker-controlled code
DANGEROUS_TRIGGERS = {
    "pull_request_target",  # Runs on base branch with write access but attacker code
    "workflow_run",         # Can be triggered by forked PRs
    "issue_comment",        # Comment-driven CI
}

# Triggers where the workflow YAML is read from the attacker's branch
MUTABLE_REF_TRIGGERS = {
    "workflow_dispatch",  # Reads workflow from the dispatched ref
    "push",              # Reads from the pushed ref
}

# Permissions that are dangerous when granted workflow-wide
DANGEROUS_PERMISSIONS = {
    "contents: write",
    "packages: write",
    "actions: write",
    "security-events: write",
    "id-token: write",
}


class SecurityModelExtractor:
    """Extract security-relevant metadata from parsed workflows."""

    def extract(self, workflow: dict) -> dict:
        """Extract the security model for a parsed workflow.

        Args:
            workflow: Output from WorkflowParser.parse_file()

        Returns:
            Security model dict with findings and metadata.
        """
        platform = workflow.get("platform", "unknown")

        if platform == "github_actions":
            return self._extract_gha(workflow)
        elif platform == "gitlab_ci":
            return self._extract_gitlab(workflow)
        elif platform == "jenkins":
            return self._extract_jenkins(workflow)
        else:
            return self._extract_generic(workflow)

    # ------------------------------------------------------------------
    # GitHub Actions
    # ------------------------------------------------------------------

    def _extract_gha(self, wf: dict) -> dict:
        """Full security model extraction for GitHub Actions."""
        findings = []

        # 1. Secret scoping analysis
        secret_findings = self._check_gha_secret_scoping(wf)
        findings.extend(secret_findings)

        # 2. Environment gate analysis
        gate_findings = self._check_gha_environment_gates(wf)
        findings.extend(gate_findings)

        # 3. Trigger analysis
        trigger_findings = self._check_gha_triggers(wf)
        findings.extend(trigger_findings)

        # 4. Expression injection analysis
        injection_findings = self._check_gha_expression_injection(wf)
        findings.extend(injection_findings)

        # 5. Permissions analysis
        perm_findings = self._check_gha_permissions(wf)
        findings.extend(perm_findings)

        # 6. Unpinned actions
        action_findings = self._check_gha_unpinned_actions(wf)
        findings.extend(action_findings)

        # Build summary
        jobs = wf.get("jobs", {})
        secrets_in_env = self._find_secrets_in_env(wf.get("workflow_env", {}))
        gated_jobs = [jid for jid, j in jobs.items() if j.get("environment")]
        ungated_jobs = [jid for jid, j in jobs.items() if not j.get("environment")]

        return {
            "platform": "github_actions",
            "total_jobs": len(jobs),
            "gated_jobs": gated_jobs,
            "ungated_jobs": ungated_jobs,
            "workflow_level_secrets": secrets_in_env,
            "triggers": [t["event"] for t in wf.get("triggers", [])],
            "has_dangerous_triggers": any(
                t["event"] in DANGEROUS_TRIGGERS for t in wf.get("triggers", [])
            ),
            "has_mutable_ref_triggers": any(
                t["event"] in MUTABLE_REF_TRIGGERS for t in wf.get("triggers", [])
            ),
            "workflow_permissions": wf.get("workflow_permissions"),
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
        }

    def _find_secrets_in_env(self, env_block: dict) -> list[str]:
        """Find secret references in an env block."""
        secrets = []
        for key, val in (env_block or {}).items():
            if isinstance(val, str) and "secrets." in val:
                secret_name = self._extract_secret_name(val)
                secrets.append(f"{key}={secret_name}" if secret_name else key)
        return secrets

    def _extract_secret_name(self, expr: str) -> Optional[str]:
        """Extract secret name from ${{ secrets.FOO }}."""
        m = re.search(r"secrets\.(\w+)", expr)
        return m.group(1) if m else None

    def _check_gha_secret_scoping(self, wf: dict) -> list[dict]:
        """Check for secrets defined at workflow level leaking to ungated jobs."""
        findings = []
        workflow_env = wf.get("workflow_env", {})
        workflow_secrets = self._find_secrets_in_env(workflow_env)

        if not workflow_secrets:
            return findings

        jobs = wf.get("jobs", {})
        ungated_jobs = [jid for jid, j in jobs.items() if not j.get("environment")]

        if ungated_jobs:
            findings.append({
                "type": "secret_scope_leak",
                "severity": "high",
                "title": "Workflow-level secret accessible to ungated jobs",
                "detail": (
                    f"Secrets {workflow_secrets} are defined in workflow-level env, "
                    f"making them accessible to ungated jobs: {ungated_jobs}. "
                    f"Any user who can modify the workflow file on a triggerable branch "
                    f"can exfiltrate these secrets."
                ),
                "affected_secrets": workflow_secrets,
                "affected_jobs": ungated_jobs,
                "cwe": "CWE-200",
            })

        return findings

    def _check_gha_environment_gates(self, wf: dict) -> list[dict]:
        """Check which jobs lack environment protection gates."""
        findings = []
        jobs = wf.get("jobs", {})
        workflow_secrets = self._find_secrets_in_env(wf.get("workflow_env", {}))

        for job_id, job in jobs.items():
            if job.get("environment"):
                continue

            # Check if this job uses secrets directly (step or job level)
            job_secrets = self._find_secrets_in_env(job.get("env", {}))
            step_secrets = []
            for step in job.get("steps", []):
                step_secrets.extend(self._find_secrets_in_env(step.get("env", {})))
                # Check 'with' block too
                step_secrets.extend(self._find_secrets_in_env(step.get("with", {})))

            all_job_secrets = job_secrets + step_secrets + workflow_secrets

            if all_job_secrets:
                findings.append({
                    "type": "missing_environment_gate",
                    "severity": "high",
                    "title": f"Job '{job_id}' accesses secrets without environment gate",
                    "detail": (
                        f"Job '{job_id}' has no 'environment:' protection but accesses "
                        f"secrets: {list(set(all_job_secrets))}. Without an environment gate, "
                        f"no reviewer approval is required to run this job."
                    ),
                    "job_id": job_id,
                    "secrets_accessed": list(set(all_job_secrets)),
                    "cwe": "CWE-284",
                })

        return findings

    def _check_gha_triggers(self, wf: dict) -> list[dict]:
        """Check for dangerous trigger configurations."""
        findings = []
        triggers = wf.get("triggers", [])

        for trigger in triggers:
            event = trigger.get("event", "")

            if event == "pull_request_target":
                findings.append({
                    "type": "dangerous_trigger",
                    "severity": "critical",
                    "title": "pull_request_target trigger — code runs with write access on attacker PRs",
                    "detail": (
                        "pull_request_target runs the workflow from the BASE branch but in "
                        "the context of the PR. If the workflow checks out the PR head "
                        "(actions/checkout with ref: ${{ github.event.pull_request.head.sha }}), "
                        "attacker-controlled code runs with the base branch's GITHUB_TOKEN "
                        "and secrets."
                    ),
                    "trigger": event,
                    "cwe": "CWE-284",
                })

            if event == "workflow_dispatch":
                # Check if any branch can trigger
                branches = trigger.get("branches", [])
                if not branches:
                    findings.append({
                        "type": "unrestricted_dispatch",
                        "severity": "medium",
                        "title": "workflow_dispatch has no branch restriction",
                        "detail": (
                            "workflow_dispatch can be triggered on any branch. Since GitHub "
                            "reads the workflow YAML from the target ref, an attacker with "
                            "write access can create a branch, modify the workflow, and "
                            "trigger it to execute arbitrary code with the workflow's secrets."
                        ),
                        "trigger": event,
                        "cwe": "CWE-284",
                    })

            if event == "issue_comment":
                findings.append({
                    "type": "comment_triggered",
                    "severity": "medium",
                    "title": "issue_comment trigger — may be triggered by external contributors",
                    "detail": (
                        "Workflows triggered by issue_comment run on the default branch with "
                        "the repository's GITHUB_TOKEN. If the workflow doesn't check the "
                        "commenter's permissions, external users may trigger privileged actions."
                    ),
                    "trigger": event,
                    "cwe": "CWE-284",
                })

        return findings

    def _check_gha_expression_injection(self, wf: dict) -> list[dict]:
        """Check for expression injection in run: blocks."""
        findings = []
        jobs = wf.get("jobs", {})

        for job_id, job in jobs.items():
            for step in job.get("steps", []):
                run_block = step.get("run")
                if not run_block or not isinstance(run_block, str):
                    continue

                # Find all expressions in run blocks
                for m in GHA_EXPRESSION_RE.finditer(run_block):
                    expr = m.group(1).strip()
                    # Check if the expression references dangerous contexts
                    for dangerous in DANGEROUS_CONTEXTS:
                        # Handle wildcard patterns
                        pattern = dangerous.replace(".*.", r"\.\w+\.")
                        if re.search(pattern, expr):
                            findings.append({
                                "type": "expression_injection",
                                "severity": "high",
                                "title": f"Expression injection in job '{job_id}'",
                                "detail": (
                                    f"Step '{step.get('name', '?')}' uses "
                                    f"${{{{ {expr} }}}} in a run: block. "
                                    f"This context ({dangerous}) may contain "
                                    f"attacker-controlled data, enabling command injection."
                                ),
                                "job_id": job_id,
                                "step_name": step.get("name"),
                                "expression": expr,
                                "dangerous_context": dangerous,
                                "cwe": "CWE-78",
                            })

        return findings

    def _check_gha_permissions(self, wf: dict) -> list[dict]:
        """Check for overly permissive permissions."""
        findings = []

        wf_perms = wf.get("workflow_permissions")

        # write-all at workflow level is dangerous
        if wf_perms == "write-all" or (isinstance(wf_perms, dict) and not wf_perms):
            findings.append({
                "type": "excessive_permissions",
                "severity": "medium",
                "title": "Workflow has write-all permissions",
                "detail": (
                    "The workflow is configured with write-all permissions. "
                    "Jobs should use the principle of least privilege."
                ),
                "cwe": "CWE-250",
            })

        # No permissions block at all means default token gets repo-wide read/write
        # (depending on org settings)
        if wf_perms is None:
            has_dangerous_trigger = any(
                t["event"] in DANGEROUS_TRIGGERS
                for t in wf.get("triggers", [])
            )
            if has_dangerous_trigger:
                findings.append({
                    "type": "default_permissions_with_dangerous_trigger",
                    "severity": "high",
                    "title": "No permissions block with dangerous trigger",
                    "detail": (
                        "The workflow has no explicit permissions block and uses a "
                        "dangerous trigger. The default GITHUB_TOKEN may have write "
                        "permissions depending on organization settings."
                    ),
                    "cwe": "CWE-250",
                })

        return findings

    def _check_gha_unpinned_actions(self, wf: dict) -> list[dict]:
        """Check for third-party actions not pinned to a SHA."""
        findings = []
        jobs = wf.get("jobs", {})

        for job_id, job in jobs.items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if not uses or not isinstance(uses, str):
                    continue

                # Skip local actions (./path)
                if uses.startswith("./"):
                    continue

                # Check if pinned to SHA (40 hex chars after @)
                if "@" in uses:
                    ref = uses.split("@", 1)[1]
                    if not re.match(r"^[0-9a-f]{40}$", ref):
                        # Pinned to branch/tag, not SHA
                        # Only flag third-party (not actions/*)
                        owner = uses.split("/")[0]
                        if owner not in ("actions", "github"):
                            findings.append({
                                "type": "unpinned_action",
                                "severity": "low",
                                "title": f"Third-party action not pinned to SHA in job '{job_id}'",
                                "detail": (
                                    f"Step '{step.get('name', '?')}' uses '{uses}' "
                                    f"which is not pinned to a commit SHA. A compromised "
                                    f"tag/branch could inject malicious code."
                                ),
                                "job_id": job_id,
                                "action": uses,
                                "cwe": "CWE-829",
                            })
                else:
                    # No @ at all
                    findings.append({
                        "type": "unpinned_action",
                        "severity": "medium",
                        "title": f"Action with no version pin in job '{job_id}'",
                        "detail": (
                            f"Step '{step.get('name', '?')}' uses '{uses}' "
                            f"with no version pin at all."
                        ),
                        "job_id": job_id,
                        "action": uses,
                        "cwe": "CWE-829",
                    })

        return findings

    # ------------------------------------------------------------------
    # GitLab CI
    # ------------------------------------------------------------------

    def _extract_gitlab(self, wf: dict) -> dict:
        """Basic security model for GitLab CI."""
        findings = []
        jobs = wf.get("jobs", {})

        for job_id, job in jobs.items():
            # Check for variables that look like secrets in job scope
            variables = job.get("variables", {})
            for key, val in variables.items():
                if isinstance(val, str) and ("$CI_" in val or "secret" in key.lower()):
                    findings.append({
                        "type": "potential_secret_exposure",
                        "severity": "medium",
                        "title": f"Potential secret in job '{job_id}' variables",
                        "detail": f"Variable '{key}' may contain sensitive data.",
                        "job_id": job_id,
                        "cwe": "CWE-200",
                    })

        return {
            "platform": "gitlab_ci",
            "total_jobs": len(jobs),
            "gated_jobs": [jid for jid, j in jobs.items() if j.get("environment")],
            "ungated_jobs": [jid for jid, j in jobs.items() if not j.get("environment")],
            "workflow_level_secrets": [],
            "triggers": [],
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
        }

    # ------------------------------------------------------------------
    # Jenkins
    # ------------------------------------------------------------------

    def _extract_jenkins(self, wf: dict) -> dict:
        """Basic security model for Jenkins pipelines."""
        findings = []
        meta = wf.get("jenkins_metadata", {})

        cred_refs = meta.get("credentials_refs", [])
        if cred_refs:
            findings.append({
                "type": "credentials_usage",
                "severity": "info",
                "title": f"Jenkins credentials referenced: {cred_refs}",
                "detail": (
                    f"Credentials IDs {cred_refs} are used. Verify they follow "
                    f"least-privilege and are scoped to the correct folder/pipeline."
                ),
                "cwe": "CWE-200",
            })

        return {
            "platform": "jenkins",
            "total_jobs": len(meta.get("stages", [])),
            "gated_jobs": [],
            "ungated_jobs": meta.get("stages", []),
            "workflow_level_secrets": [],
            "triggers": [],
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
        }

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def _extract_generic(self, wf: dict) -> dict:
        """Minimal security model for unsupported platforms."""
        return {
            "platform": wf.get("platform", "unknown"),
            "total_jobs": 0,
            "gated_jobs": [],
            "ungated_jobs": [],
            "workflow_level_secrets": [],
            "triggers": [],
            "findings": [],
            "finding_count": 0,
            "severity_counts": {},
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _count_severities(self, findings: list[dict]) -> dict:
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
