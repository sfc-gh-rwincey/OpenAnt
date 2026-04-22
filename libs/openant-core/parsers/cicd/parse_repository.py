#!/usr/bin/env python3
"""
CI/CD Repository Parser — Main Orchestrator

Entry point for parsing CI/CD configurations into OpenAnt datasets.
Runs the pipeline: Scan → Parse → Security Model → Unit Generation.

Output files match the standard OpenAnt format:
- dataset.json: Analysis units (one per workflow/pipeline)
- analyzer_output.json: Minimal index for compatibility

Usage:
    python parse_repository.py /path/to/repo --output dataset.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from parsers.cicd.workflow_scanner import CICDScanner
    from parsers.cicd.workflow_parser import WorkflowParser
    from parsers.cicd.security_model import SecurityModelExtractor
except ImportError:
    from workflow_scanner import CICDScanner
    from workflow_parser import WorkflowParser
    from security_model import SecurityModelExtractor


# File boundary marker (matches the convention in other parsers)
FILE_BOUNDARY = "\n\n# ========== File Boundary ==========\n\n"


def parse_repository(
    repo_path: str,
    output_dir: str,
    skip_tests: bool = True,
    name: str = None,
    file_filter: set = None,
) -> dict:
    """Parse CI/CD configurations into an OpenAnt dataset.

    Args:
        repo_path: Absolute path to the repository.
        output_dir: Directory for output files.
        skip_tests: Unused (kept for interface compat).
        name: Dataset name override.
        file_filter: Optional set of repo-relative paths; only matching
            CI/CD files will be included.

    Returns:
        {"dataset_path": ..., "analyzer_output_path": ..., "units_count": ..., "language": "cicd"}
    """
    repo_path = str(Path(repo_path).resolve())
    output_dir = str(Path(output_dir).resolve())
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    dataset_name = name or Path(repo_path).name

    # Phase 1: Scan
    scanner = CICDScanner(repo_path)
    scan_result = scanner.scan()
    files = scan_result["files"]

    # Apply git diff file filter if provided
    if file_filter and files:
        files = [f for f in files if f["path"].replace("\\", "/") in file_filter]

    if not files:
        # No CI/CD files found — return empty dataset
        dataset = _empty_dataset(dataset_name, repo_path)
        return _write_outputs(dataset, output_dir, repo_path)

    print(f"  Found {len(files)} CI/CD config files "
          f"({', '.join(scan_result['platforms_detected'])})",
          file=sys.stderr)

    # Phase 2: Parse
    parser = WorkflowParser(repo_path)
    workflows = []
    for file_info in files:
        wf = parser.parse_file(file_info["path"], file_info["platform"])
        if wf:
            workflows.append(wf)

    # Phase 3: Security model extraction
    extractor = SecurityModelExtractor()
    for wf in workflows:
        wf["security_model"] = extractor.extract(wf)

    # Phase 4: Generate units
    units = []
    functions_index = {}

    for wf in workflows:
        unit = _workflow_to_unit(wf)
        units.append(unit)

        # Build a minimal functions index for Stage 2 compatibility
        unit_id = unit["id"]
        functions_index[unit_id] = {
            "name": wf.get("name", unit_id),
            "code": wf.get("raw_content", ""),
            "isExported": True,
            "unitType": "cicd_workflow",
            "file_path": wf["file_path"],
        }

    # Build dataset
    dataset = {
        "name": dataset_name,
        "repository": repo_path,
        "language": "cicd",
        "generated_at": datetime.now().isoformat(),
        "parser": "openant-cicd-parser",
        "parser_version": "0.1.0",
        "units": units,
        "statistics": {
            "total_units": len(units),
            "platforms": scan_result["platforms_detected"],
            "total_static_findings": sum(
                wf.get("security_model", {}).get("finding_count", 0)
                for wf in workflows
            ),
        },
    }

    return _write_outputs(dataset, output_dir, repo_path, functions_index)


def _workflow_to_unit(wf: dict) -> dict:
    """Convert a parsed workflow into an OpenAnt analysis unit.

    The unit format is compatible with experiment.py / core/analyzer.py:
    - id: unique identifier
    - unit_type: "cicd_workflow"
    - code: {"primary_code": ..., "primary_origin": ...}
    - security_model: pre-extracted structural findings
    """
    file_path = wf["file_path"]
    platform = wf["platform"]
    wf_name = wf.get("name", Path(file_path).stem)
    unit_id = f"cicd:{platform}:{file_path}"

    # The "code" for a CI/CD unit is the raw workflow content
    raw_content = wf.get("raw_content", "")

    # Build a structured summary to prepend for the LLM
    security_model = wf.get("security_model", {})
    summary_lines = [
        f"# CI/CD Workflow: {wf_name}",
        f"# Platform: {platform}",
        f"# File: {file_path}",
        f"# Triggers: {', '.join(security_model.get('triggers', []))}",
        f"# Jobs: {security_model.get('total_jobs', 0)} total, "
        f"{len(security_model.get('gated_jobs', []))} gated, "
        f"{len(security_model.get('ungated_jobs', []))} ungated",
    ]

    if security_model.get("workflow_level_secrets"):
        summary_lines.append(
            f"# Workflow-level secrets: {', '.join(security_model['workflow_level_secrets'])}"
        )

    static_findings = security_model.get("findings", [])
    if static_findings:
        summary_lines.append(f"# Static findings: {len(static_findings)}")
        for sf in static_findings:
            summary_lines.append(f"#   [{sf['severity'].upper()}] {sf['title']}")

    summary = "\n".join(summary_lines)

    # Combine summary + raw content as the "primary_code"
    primary_code = summary + "\n\n" + raw_content

    return {
        "id": unit_id,
        "unit_type": "cicd_workflow",
        "code": {
            "primary_code": primary_code,
            "primary_origin": {
                "file_path": file_path,
                "start_line": 1,
                "end_line": raw_content.count("\n") + 1,
                "function_name": wf_name,
                "class_name": None,
                "enhanced": False,
                "files_included": [file_path],
            },
        },
        "security_model": security_model,
        "metadata": {
            "platform": platform,
            "workflow_name": wf_name,
            "triggers": security_model.get("triggers", []),
            "total_jobs": security_model.get("total_jobs", 0),
            "gated_jobs": security_model.get("gated_jobs", []),
            "ungated_jobs": security_model.get("ungated_jobs", []),
            "static_finding_count": security_model.get("finding_count", 0),
        },
        "ground_truth": {"status": "UNKNOWN"},
    }


def _empty_dataset(name: str, repo_path: str) -> dict:
    return {
        "name": name,
        "repository": repo_path,
        "language": "cicd",
        "generated_at": datetime.now().isoformat(),
        "parser": "openant-cicd-parser",
        "parser_version": "0.1.0",
        "units": [],
        "statistics": {"total_units": 0, "platforms": [], "total_static_findings": 0},
    }


def _write_outputs(
    dataset: dict,
    output_dir: str,
    repo_path: str,
    functions_index: dict = None,
) -> dict:
    """Write dataset.json and analyzer_output.json."""
    dataset_path = str(Path(output_dir) / "dataset.json")
    analyzer_output_path = str(Path(output_dir) / "analyzer_output.json")

    with open(dataset_path, "w") as f:
        json.dump(dataset, f, indent=2)

    # Minimal analyzer_output for Stage 2 compatibility
    analyzer_output = {
        "repository": repo_path,
        "language": "cicd",
        "functions": functions_index or {},
    }
    with open(analyzer_output_path, "w") as f:
        json.dump(analyzer_output, f, indent=2)

    return {
        "dataset_path": dataset_path,
        "analyzer_output_path": analyzer_output_path,
        "units_count": len(dataset["units"]),
        "language": "cicd",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Parse CI/CD configs for OpenAnt")
    parser.add_argument("repo", help="Path to repository")
    parser.add_argument("--output", "-o", default=".", help="Output directory")
    parser.add_argument("--name", default=None, help="Dataset name")
    args = parser.parse_args()

    result = parse_repository(args.repo, args.output, name=args.name)
    json.dump(result, sys.stdout, indent=2)
    print(file=sys.stdout)


if __name__ == "__main__":
    main()
