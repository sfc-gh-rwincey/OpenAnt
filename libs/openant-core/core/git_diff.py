"""
Git diff file resolver.

Resolves the set of files changed in a git repository, filtered by:
  - Time: ``--since "1 week ago"`` (uses ``git log --since``)
  - Base ref: ``--diff-base main`` (uses ``git diff <ref>...HEAD``)

Returns a set of *relative* paths (repo-root-relative, forward-slash
separated) that the parser layer uses to restrict which files enter the
pipeline.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Set


def _run_git(repo_path: str, args: list[str]) -> str:
    """Run a git command inside *repo_path* and return stdout."""
    result = subprocess.run(
        ["git", "-C", repo_path] + args,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    return result.stdout


def resolve_changed_files(
    repo_path: str,
    *,
    since: Optional[str] = None,
    diff_base: Optional[str] = None,
) -> Set[str]:
    """Return the set of changed file paths relative to the repo root.

    Exactly one of *since* or *diff_base* must be provided.

    Args:
        repo_path: Absolute path to the repository.
        since: A git-compatible date expression, e.g. ``"1 week ago"``,
            ``"2025-04-01"``.  Resolves via ``git log --since``.
        diff_base: A branch, tag, or commit SHA to diff against HEAD.
            Resolves via ``git diff <ref>...HEAD``.

    Returns:
        A set of repo-relative file paths (forward-slash separated) that
        were Added, Copied, Modified, or Renamed (ACMR) in the resolved
        range.

    Raises:
        ValueError: If neither or both arguments are provided, or if the
            path is not a git repository.
        RuntimeError: If the underlying git command fails.
    """
    if not since and not diff_base:
        raise ValueError("One of --since or --diff-base is required")
    if since and diff_base:
        raise ValueError("Only one of --since or --diff-base may be used")

    repo_path = os.path.abspath(repo_path)

    # Verify this is a git repository
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.isdir(git_dir):
        raise ValueError(
            f"Not a git repository (no .git directory): {repo_path}"
        )

    if since:
        # Get all files touched in commits since the given date
        raw = _run_git(repo_path, [
            "log",
            f"--since={since}",
            "--diff-filter=ACMR",
            "--name-only",
            "--pretty=format:",
        ])
    else:
        # Diff from merge-base of diff_base and HEAD
        raw = _run_git(repo_path, [
            "diff",
            "--diff-filter=ACMR",
            "--name-only",
            f"{diff_base}...HEAD",
        ])

    # Parse output: one file per line, skip blanks
    files: Set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if line:
            # Normalise to forward-slash
            files.add(line.replace("\\", "/"))

    print(
        f"  [Git filter] {len(files)} changed files "
        f"({'since ' + since if since else 'vs ' + diff_base})",
        file=sys.stderr,
    )

    return files
