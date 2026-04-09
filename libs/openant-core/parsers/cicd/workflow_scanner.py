#!/usr/bin/env python3
"""
CI/CD Workflow Scanner

Discovers CI/CD configuration files in a repository:
- GitHub Actions: .github/workflows/*.yml
- GitLab CI: .gitlab-ci.yml
- Jenkins: Jenkinsfile*, jenkins/*.groovy
- Azure Pipelines: azure-pipelines.yml, .azure-pipelines/*.yml
- CircleCI: .circleci/config.yml

This is Phase 1 of the CI/CD parser — file discovery.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set


# CI/CD platform detection patterns
CICD_PATTERNS = {
    "github_actions": {
        "globs": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "description": "GitHub Actions workflows",
    },
    "gitlab_ci": {
        "globs": [".gitlab-ci.yml", ".gitlab-ci.yaml"],
        "description": "GitLab CI/CD pipeline",
    },
    "jenkins": {
        "globs": ["Jenkinsfile", "Jenkinsfile.*", "jenkins/*.groovy"],
        "description": "Jenkins pipeline",
    },
    "azure_pipelines": {
        "globs": [
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            ".azure-pipelines/*.yml",
            ".azure-pipelines/*.yaml",
        ],
        "description": "Azure DevOps Pipelines",
    },
    "circleci": {
        "globs": [".circleci/config.yml", ".circleci/config.yaml"],
        "description": "CircleCI pipeline",
    },
}


class CICDScanner:
    """Scan a repository for CI/CD configuration files."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()

    def scan(self) -> dict:
        """Discover all CI/CD config files.

        Returns:
            {
                "repository": "/path/to/repo",
                "scan_time": "...",
                "files": [{"path": "relative/path", "platform": "github_actions", "size": N}],
                "platforms_detected": ["github_actions", ...],
                "statistics": {"total_files": N, ...}
            }
        """
        files = []
        platforms_detected = set()

        for platform, config in CICD_PATTERNS.items():
            for glob_pattern in config["globs"]:
                for match in self.repo_path.glob(glob_pattern):
                    if match.is_file():
                        rel_path = str(match.relative_to(self.repo_path))
                        files.append({
                            "path": rel_path,
                            "platform": platform,
                            "size": match.stat().st_size,
                        })
                        platforms_detected.add(platform)

        return {
            "repository": str(self.repo_path),
            "scan_time": datetime.now().isoformat(),
            "files": sorted(files, key=lambda f: f["path"]),
            "platforms_detected": sorted(platforms_detected),
            "statistics": {
                "total_files": len(files),
                "platforms": len(platforms_detected),
            },
        }
