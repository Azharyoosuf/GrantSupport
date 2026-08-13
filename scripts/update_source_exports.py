#!/usr/bin/env python3
"""
Utility script to regenerate GRANTSUPPORT_FULL_SOURCE.md and GRANTSUPPORT_GENERATED_ENT_SOURCE.md
from the live codebase.
"""

import os
import subprocess
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def get_git_commit():
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "HEAD"

def make_anchor(filepath):
    anchor = filepath.replace("/", "-").replace("\\", "-").replace(".", "-").replace("_", "-").lower()
    return anchor

def get_lang(filepath):
    if filepath.endswith(".go"):
        return "go"
    if filepath.endswith(".py"):
        return "python"
    if filepath.endswith(".mod") or filepath.endswith(".sum"):
        return "text"
    if filepath.endswith(".md"):
        return "markdown"
    if filepath.endswith(".json"):
        return "json"
    if filepath.endswith(".yaml") or filepath.endswith(".yml"):
        return "yaml"
    if filepath.endswith(".sql"):
        return "sql"
    if filepath.lower().endswith("dockerfile"):
        return "dockerfile"
    return "text"

def generate_full_source():
    commit = get_git_commit()
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Categories
    cmd_files = []
    pkg_files = []
    ent_schema_files = []
    api_files = []
    migration_files = []
    docs_files = []
    script_files = []
    root_files = ["README.md", "Dockerfile", "docker-compose.yml", "go.mod", "go.sum"]

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "cmd")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            cmd_files.append(rel)

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "pkg")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            pkg_files.append(rel)

    ent_schema_files.append("ent/generate.go")
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "ent", "schema")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            ent_schema_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "api")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "api")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                api_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "migrations")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "migrations")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                migration_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "docs")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "docs")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                docs_files.append(rel)

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "scripts")):
        for f in sorted(files):
            if f.endswith(".py"):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                script_files.append(rel)

    cmd_files.sort()
    pkg_files.sort()
    ent_schema_files.sort()
    api_files.sort()
    migration_files.sort()
    docs_files.sort()
    script_files.sort()

    lines = []
    lines.append("# GrantSupport Full Source Code Export")
    lines.append("")
    lines.append(f"- **Export Date**: {date_str}")
    lines.append(f"- **Git Commit**: {commit}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append("")

    if cmd_files:
        lines.append("### cmd/")
        for f in cmd_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if pkg_files:
        lines.append("### pkg/")
        for f in pkg_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if ent_schema_files:
        lines.append("### ent/schema/")
        for f in ent_schema_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if api_files:
        lines.append("### api/")
        for f in api_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if migration_files:
        lines.append("### migrations/")
        for f in migration_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if docs_files:
        lines.append("### docs/")
        for f in docs_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if script_files:
        lines.append("### scripts/")
        for f in script_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if root_files:
        lines.append("### Root-level files")
        for f in root_files:
            if os.path.exists(os.path.join(REPO_ROOT, f)):
                lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    lines.append("---")
    lines.append("")

    all_sections = [
        ("cmd", cmd_files),
        ("pkg", pkg_files),
        ("ent/schema", ent_schema_files),
        ("api", api_files),
        ("migrations", migration_files),
        ("docs", docs_files),
        ("scripts", script_files),
        ("root", [f for f in root_files if os.path.exists(os.path.join(REPO_ROOT, f))])
    ]

    for cat, files in all_sections:
        for f in files:
            full_path = os.path.join(REPO_ROOT, f)
            if not os.path.exists(full_path):
                continue
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            lang = get_lang(f)
            lines.append(f"## {f}")
            lines.append("")
            lines.append(f"```{lang}")
            lines.append(content.rstrip())
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

    out_path = os.path.join(REPO_ROOT, "GRANTSUPPORT_FULL_SOURCE.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    print(f"Generated {out_path} ({len(lines)} lines)")

def generate_generated_ent_source():
    date_str = datetime.now().strftime("%Y-%m-%d")

    ent_files = []
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "ent")):
        # Skip schema directory and generate.go
        rel_root = os.path.relpath(root, REPO_ROOT).replace(os.sep, "/")
        if rel_root.startswith("ent/schema"):
            continue
        for f in sorted(files):
            if f == "generate.go":
                continue
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            ent_files.append(rel)

    ent_files.sort()

    lines = []
    lines.append("# GrantSupport Generated Ent Code Export")
    lines.append("")
    lines.append(f"- **Export Date**: {date_str}")
    lines.append("- **Description**: Contains the generated Ent ORM boilerplate code omitted from GRANTSUPPORT_FULL_SOURCE.md.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append("")
    for f in ent_files:
        lines.append(f"- [{f}](#{make_anchor(f)})")
    lines.append("")
    lines.append("---")
    lines.append("")

    for f in ent_files:
        full_path = os.path.join(REPO_ROOT, f)
        if not os.path.exists(full_path):
            continue
        with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        lang = get_lang(f)
        lines.append(f"## {f}")
        lines.append("")
        lines.append(f"```{lang}")
        lines.append(content.rstrip())
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    out_path = os.path.join(REPO_ROOT, "GRANTSUPPORT_GENERATED_ENT_SOURCE.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    print(f"Generated {out_path} ({len(lines)} lines)")

if __name__ == "__main__":
    generate_full_source()
    generate_generated_ent_source()
