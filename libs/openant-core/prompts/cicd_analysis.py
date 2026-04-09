"""
CI/CD Configuration Security Analysis Prompts

Stage 1 and Stage 2 prompts for analyzing CI/CD pipeline configurations.
These are structurally different from code-analysis prompts because:

1. The "code" is declarative configuration (YAML/Groovy), not executable code
2. Vulnerabilities are structural/scoping issues, not data-flow issues
3. The threat model involves CI/CD-specific attack patterns (secret exfiltration,
   supply chain poisoning, privilege escalation within the pipeline)
4. Static pre-analysis (security_model) is available to guide the LLM

Supported platforms: GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI.
"""

from typing import Optional


# ---------------------------------------------------------------------------
# Stage 1: Detection
# ---------------------------------------------------------------------------

CICD_SYSTEM_PROMPT = """You are a CI/CD security specialist. You analyze pipeline configurations for real, exploitable misconfigurations.

Your threat model:
- **Attacker profile:** A developer with write access to the repository (insider threat), or an external contributor who can open PRs/issues.
- **Goal:** Exfiltrate secrets, inject malicious code into builds/releases, escalate privileges, or establish persistence in the CI/CD pipeline.

CI/CD-specific vulnerability classes you look for:
1. **Secret scope leaks:** Secrets defined at workflow/pipeline level accessible to jobs without approval gates
2. **Missing environment gates:** Jobs that access secrets without deployment environment protection
3. **Dangerous triggers:** pull_request_target, workflow_dispatch on mutable refs, issue_comment without permission checks
4. **Expression/script injection:** Attacker-controlled data (${{ github.event.*.title }}) interpolated into run: blocks
5. **Overly permissive permissions:** write-all or broad GITHUB_TOKEN scopes
6. **Unpinned dependencies:** Third-party actions/images not pinned to SHA digests
7. **Branch protection gaps:** Trigger patterns that match unprotected branch namespaces
8. **Self-hosted runner abuse:** Workflows that run on self-hosted runners without isolation

Be skeptical. Not every finding from the static pre-analysis is exploitable. Consider:
- Whether the attacker can actually reach the vulnerable job (branch protections, trigger restrictions)
- Whether the secret is actually sensitive (some env vars are non-secret)
- Whether platform-level protections (required reviewers, branch rulesets) mitigate the issue
- Whether the "vulnerability" is actually standard practice for the platform"""


def get_cicd_system_prompt() -> str:
    """Return the system prompt for CI/CD Stage 1 analysis."""
    return CICD_SYSTEM_PROMPT


def get_cicd_analysis_prompt(
    code: str,
    platform: str,
    workflow_name: str,
    security_model: dict,
    file_path: str,
) -> str:
    """Generate the Stage 1 CI/CD analysis prompt.

    Args:
        code: The raw workflow content (with summary header prepended).
        platform: CI/CD platform (github_actions, gitlab_ci, jenkins, etc.)
        workflow_name: Human-readable workflow name.
        security_model: Pre-extracted security model from SecurityModelExtractor.
        file_path: Path to the workflow file relative to repo root.

    Returns:
        Formatted prompt string.
    """
    # Build static findings summary
    static_findings = security_model.get("findings", [])
    findings_section = ""
    if static_findings:
        findings_section = "\n## Pre-Analysis Findings (from static extraction)\n\n"
        findings_section += "These were identified by structural analysis. Evaluate whether each is truly exploitable:\n\n"
        for i, f in enumerate(static_findings, 1):
            findings_section += (
                f"{i}. **[{f['severity'].upper()}] {f['title']}**\n"
                f"   {f['detail']}\n"
                f"   CWE: {f.get('cwe', 'N/A')}\n\n"
            )
    else:
        findings_section = "\n## Pre-Analysis Findings\n\nNo structural issues detected by static analysis.\n\n"

    # Build structural summary
    gated = security_model.get("gated_jobs", [])
    ungated = security_model.get("ungated_jobs", [])
    triggers = security_model.get("triggers", [])
    wf_secrets = security_model.get("workflow_level_secrets", [])

    structure_section = f"""## Workflow Structure

- **Platform:** {platform}
- **Triggers:** {', '.join(triggers) if triggers else 'none detected'}
- **Total jobs:** {security_model.get('total_jobs', 0)}
- **Environment-gated jobs:** {', '.join(gated) if gated else 'none'}
- **Ungated jobs:** {', '.join(ungated) if ungated else 'none'}
- **Workflow-level secrets:** {', '.join(wf_secrets) if wf_secrets else 'none'}
- **Workflow permissions:** {security_model.get('workflow_permissions', 'default (not specified)')}
"""

    platform_guidance = _get_platform_guidance(platform)

    return f"""Analyze this CI/CD configuration for security vulnerabilities.

{structure_section}
{findings_section}
{platform_guidance}

## Configuration File: `{file_path}`

```yaml
{code}
```

## Your Analysis

For each potential vulnerability, think through:

1. **What is the misconfiguration?** (Be specific — which field, which job, which scope)

2. **Who can exploit it?** Consider:
   - Any developer with write access to the repo?
   - External contributors (PR authors, issue commenters)?
   - Only repository admins?

3. **What is the attack path?**
   - Can the attacker create a branch that triggers this workflow?
   - Does the workflow read its YAML from the attacker's branch?
   - Can the attacker modify job steps on their branch?
   - Does the attacker need to bypass any approval gates?

4. **What does the attacker gain?**
   - Secret exfiltration (which secrets, what scopes)?
   - Code injection into builds/releases (supply chain impact)?
   - Lateral movement to other repos/services?
   - Persistence mechanisms?

5. **Could you be wrong?**
   - Are there branch protection rules you can't see from the YAML alone?
   - Does the platform have default protections for this scenario?
   - Is this actually standard/expected practice?

## Response Format

{{
    "function_analyzed": "{workflow_name} ({file_path})",
    "finding": "safe" | "protected" | "vulnerable" | "inconclusive",
    "reasoning": "Your analysis of the configuration",
    "vulnerabilities": [
        {{
            "title": "Short title",
            "severity": "critical" | "high" | "medium" | "low",
            "attack_vector": "Detailed exploitation scenario",
            "affected_jobs": ["job_id1", "job_id2"],
            "affected_secrets": ["SECRET_NAME"],
            "cwe": "CWE-XXX",
            "remediation": "Specific fix"
        }}
    ],
    "attack_vector": "Primary attack scenario if vulnerable, null if safe",
    "confidence": 0.0-1.0
}}

**Default to SAFE unless you can describe a specific, realistic attack path.**"""


def _get_platform_guidance(platform: str) -> str:
    """Platform-specific analysis guidance."""
    if platform == "github_actions":
        return """## GitHub Actions Security Model

Key facts for your analysis:
- `workflow_dispatch` reads the workflow YAML from the **target branch** (attacker controls content if they can push to it)
- `pull_request` reads from the PR merge commit but runs with READ-ONLY token and NO access to secrets
- `pull_request_target` reads from the BASE branch but can checkout PR head — this is the classic attack vector
- `environment:` gates require reviewer approval before the job runs — secrets in gated jobs are protected
- Workflow-level `env:` makes secrets available to ALL jobs, including ungated ones
- The default `GITHUB_TOKEN` permissions depend on org settings (may be read-only or read-write)
- Branch protection rules and rulesets are NOT visible in the workflow YAML — note assumptions
- `${{ }}` expressions in `run:` blocks are interpolated BEFORE the shell runs — this enables injection
- Secrets are masked in logs but can be exfiltrated via network or encoded output"""

    elif platform == "gitlab_ci":
        return """## GitLab CI Security Model

Key facts:
- Protected variables are only available on protected branches/tags
- CI_JOB_TOKEN has limited scope by default but can be configured
- `rules:` and `only:`/`except:` control which branches trigger jobs
- `environment:` with `deployment_tier: production` can require approvals"""

    elif platform == "jenkins":
        return """## Jenkins Security Model

Key facts:
- Credentials are stored in Jenkins credential store, not in the pipeline file
- `credentials()` binding scopes matter (folder vs global)
- Pipeline libraries can inject code into the build
- Shared libraries with @Grab can pull arbitrary dependencies
- Jenkinsfile from SCM reads from the branch being built (similar to workflow_dispatch)"""

    return ""


# ---------------------------------------------------------------------------
# Stage 2: Verification
# ---------------------------------------------------------------------------

CICD_VERIFICATION_SYSTEM_PROMPT = """You are a CI/CD penetration tester. You only report misconfigurations you can actually exploit.

You understand GitHub Actions, GitLab CI, Jenkins, and other CI/CD platforms deeply.
You know the difference between theoretical risk and actual exploitability.
You consider platform-level mitigations that may not be visible in the YAML."""


def get_cicd_verification_system_prompt() -> str:
    """Return the system prompt for CI/CD Stage 2 verification."""
    return CICD_VERIFICATION_SYSTEM_PROMPT


def get_cicd_verification_prompt(
    code: str,
    finding: str,
    attack_vector: str,
    reasoning: str,
    vulnerabilities: list = None,
    platform: str = "github_actions",
    security_model: dict = None,
) -> str:
    """Generate the Stage 2 CI/CD verification prompt.

    Args:
        code: The raw workflow content.
        finding: Stage 1 finding (vulnerable/safe/etc).
        attack_vector: Stage 1 claimed attack vector.
        reasoning: Stage 1 reasoning.
        vulnerabilities: List of specific vulnerability dicts from Stage 1.
        platform: CI/CD platform.
        security_model: Pre-extracted security model.

    Returns:
        Formatted verification prompt.
    """
    vuln_section = ""
    if vulnerabilities:
        vuln_section = "\n**Specific claims to verify:**\n"
        for i, v in enumerate(vulnerabilities, 1):
            vuln_section += (
                f"\n{i}. **{v.get('title', 'Unknown')}** ({v.get('severity', '?')})\n"
                f"   Attack: {v.get('attack_vector', 'Not specified')}\n"
                f"   Affected: jobs={v.get('affected_jobs', [])}, "
                f"secrets={v.get('affected_secrets', [])}\n"
            )

    model_section = ""
    if security_model:
        ungated = security_model.get("ungated_jobs", [])
        gated = security_model.get("gated_jobs", [])
        wf_secrets = security_model.get("workflow_level_secrets", [])
        model_section = f"""
**Structural context:**
- Ungated jobs: {ungated}
- Gated jobs: {gated}
- Workflow-level secrets: {wf_secrets}
"""

    return f"""Stage 1 claims this CI/CD configuration is **{finding.upper()}**.

Their reasoning: {reasoning}
{vuln_section}
{model_section}

## Configuration

```yaml
{code}
```

---

You are an attacker with write access to this repository (you can push branches and trigger workflows). For each claimed vulnerability, attempt to exploit it:

**For each claim, trace the full attack path:**

1. **Branch creation:** Can you create a branch that matches the trigger pattern? Are there rulesets preventing this?

2. **Workflow modification:** If you push a modified workflow to your branch, will the CI/CD platform read YOUR version or the one from the default branch?

3. **Secret access:** If the workflow runs your modified version, which secrets are in scope? Are any gated behind environment approvals you can't bypass?

4. **Exfiltration:** How would you extract the secret? Network egress? Encoded log output? Modified build artifacts?

5. **Impact:** What can you do with the exfiltrated secret? What's the blast radius?

**IMPORTANT considerations:**
- Branch protection rules and rulesets are NOT visible in this YAML. Note this as an assumption.
- Organization-level settings (default token permissions, fork PR policies) are not visible. Note assumptions.
- If exploitation requires assumptions about missing protections, state them explicitly.
- If the attack path is blocked by a platform mechanism, explain which one.

{{
    "agree": true | false,
    "correct_finding": "safe" | "protected" | "vulnerable" | "bypassable" | "inconclusive",
    "explanation": "Your detailed verification analysis",
    "exploit_path": {{
        "entry_point": "How the attacker triggers the pipeline",
        "data_flow": ["Step 1", "Step 2", "..."],
        "sink": "What the attacker gains",
        "blocked_by": null | "Description of what blocks exploitation"
    }},
    "assumptions": ["List of assumptions about non-visible protections"],
    "verified_vulnerabilities": [
        {{
            "title": "...",
            "confirmed": true | false,
            "exploitation_detail": "...",
            "assumptions": ["..."]
        }}
    ]
}}"""
