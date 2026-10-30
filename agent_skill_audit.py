"""Offline, heuristic review hints for agent skills. Never executes target files."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import quote

VERSION = "0.2.0"
MAX_BYTES = 1_048_576
MAX_ENTRIES = 20_000
MAX_LINE_CHARS = 8192
MAX_FINDINGS = 10_000
MAX_TOTAL_BYTES = 32 * 1_048_576
IGNORED = {".git", ".venv", "venv", "node_modules", "__pycache__"}
EXTENSIONS = {".md", ".mdx", ".txt", ".py", ".sh", ".bash", ".ps1", ".bat", ".cmd",
              ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".env"}
# Each match is a review hint, not a verdict about intent or exploitability.
RULES = [
    ("ASA001", "high", "Remote content piped into an interpreter",
     r"\b(?:curl|wget)\b[^\r\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    ("ASA002", "high", "PowerShell remote or encoded execution",
     r"(?:\b(?:iex|Invoke-Expression)\b[^\r\n]*\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b|"
     r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]*\|\s*(?:iex|Invoke-Expression)\b|"
     r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*\s-(?:enc|encodedcommand)\b)"),
    ("ASA003", "high", "Recursive deletion requires path and scope review",
     r"(?:\brm\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*r[A-Za-z]*\b|"
     r"\bRemove-Item\b[^\r\n]*-Recurse\b|\bshutil\.rmtree\s*\()"),
    ("ASA004", "medium", "Instruction attempts to override prior instructions",
     r"(?:\b(?:ignore|disregard|override)\s+(?:(?:all|the|your)\s+)*(?:previous|prior|system|developer)\s+(?:instructions?|prompts?|messages?)\b|"
     r"忽略.{0,12}(?:之前|先前|系统|开发者).{0,8}(?:指令|提示))"),
    ("ASA005", "medium", "Reference to credentials or sensitive local files",
     r"(?:\.ssh[/\\]|\.aws[/\\]credentials\b|\bid_rsa\b|\b(?:OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\b)"),
    ("ASA006", "high", "Token-shaped value or private key marker",
     r"(?:\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
    ("ASA007", "medium", "Shell execution or dynamically evaluated code",
     r"(?:\bshell\s*=\s*True\b|\bos\.system\s*\(|(?<![\w.])(?:eval|exec)\(|"
     r"\b(?:child_process|childProcess)\.exec(?:Sync)?\s*\(|\bInvoke-Expression\b)"),
    ("ASA008", "medium", "Upload or HTTP write requires destination review",
     r"(?:\bcurl\b[^\r\n]*(?:--data(?:-binary|-raw)?\b|--upload-file\b|\s-[dTF]\b)|"
     r"\brequests\.(?:post|put|patch)\s*\(|\bInvoke-RestMethod\b[^\r\n]*-Method\s+(?:Post|Put|Patch)\b)"),
]
COMPILED = [(i, level, msg, re.compile(expr, re.I)) for i, level, msg, expr in RULES]


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def scan(root: Path, *, max_bytes: int = MAX_BYTES, max_entries: int = MAX_ENTRIES,
         max_line_chars: int = MAX_LINE_CHARS, max_findings: int = MAX_FINDINGS,
         max_total_bytes: int = MAX_TOTAL_BYTES) -> dict:
    """Read a stable local tree. Not a sandbox against concurrent filesystem changes."""
    root = Path(os.path.abspath(root))
    if min(max_bytes, max_entries, max_line_chars, max_findings, max_total_bytes) < 1:
        raise ValueError("Scan limits must be positive")
    if is_link(root) or not root.is_dir():
        raise ValueError("Target must be a regular directory, not a link or reparse point")
    result = {"tool": "agent-skill-audit", "version": VERSION,
              "files_scanned": 0, "entries_seen": 0, "excluded_entries": 0,
              "findings": [], "skipped": [], "incomplete": False, "bytes_read": 0}

    def skip(path: Path, reason: str) -> None:
        result["incomplete"] = True
        try:
            name = path.relative_to(root).as_posix()
        except ValueError:
            name = "."
        result["skipped"].append({"path": name, "reason": reason})

    def walk_error(error: OSError) -> None:
        skip(Path(error.filename) if error.filename else root, "unreadable_directory")

    exhausted = False
    for base, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs.sort()
        files.sort()
        directory_names = set(dirs)
        allowed = []
        for name in dirs + files:
            result["entries_seen"] += 1
            if result["entries_seen"] > max_entries:
                skip(root, "entry_limit")
                exhausted = True
                break
            path = Path(base) / name
            if name in IGNORED:
                result["excluded_entries"] += 1
                continue
            try:
                if is_link(path):
                    skip(path, "link_or_reparse_point")
                    continue
                if name in directory_names:
                    allowed.append(name)
                    continue
                if path.suffix.lower() not in EXTENSIONS and path.name != ".env":
                    result["excluded_entries"] += 1
                    continue
                if not stat.S_ISREG(path.stat().st_mode):
                    skip(path, "not_regular_file")
                    continue
                with path.open("rb") as handle:
                    remaining = max_total_bytes - result["bytes_read"]
                    raw = handle.read(min(max_bytes + 1, remaining + 1))
                result["bytes_read"] += len(raw)
                if result["bytes_read"] > max_total_bytes:
                    skip(path, "total_bytes_limit")
                    exhausted = True
                    break
                if len(raw) > max_bytes:
                    skip(path, "file_size_limit")
                    continue
                if b"\x00" in raw:
                    skip(path, "binary_or_unsupported_encoding")
                    continue
                try:
                    contents = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    skip(path, "unsupported_encoding")
                    continue
            except OSError:
                skip(path, "unreadable_file")
                continue
            result["files_scanned"] += 1
            long_lines = False
            for line_num, line in enumerate(contents.splitlines(), 1):
                if len(line) > max_line_chars:
                    long_lines = True
                    continue
                for rule_id, severity, message, pattern in COMPILED:
                    if pattern.search(line):
                        if len(result["findings"]) >= max_findings:
                            skip(path, "findings_limit")
                            exhausted = True
                            break
                        result["findings"].append({"rule": rule_id, "severity": severity,
                            "path": path.relative_to(root).as_posix(), "line": line_num,
                            "kind": "documentation" if path.suffix.lower() in {".md", ".mdx", ".txt"} else "source_or_config",
                            "message": message})
                if exhausted:
                    break
            if long_lines:
                skip(path, "line_length_limit")
            if exhausted:
                break
        dirs[:] = allowed
        if exhausted:
            break
    return result


def to_sarif(report: dict) -> dict:
    """SARIF 2.1.0 review hints without source excerpts or absolute paths."""
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "agent-skill-audit", "version": VERSION,
                "rules": [{"id": i, "shortDescription": {"text": msg}} for i, _, msg, _ in RULES]}},
                "invocations": [{"executionSuccessful": not report.get("incomplete", True),
                    "toolExecutionNotifications": [{"level": "warning", "message": {"text": "Scan incomplete; inspect JSON output for skipped files."}}]
                    if report.get("incomplete", True) else []}],
                "results": [{"ruleId": f["rule"], "level": "warning" if f["severity"] == "high" else "note",
                    "message": {"text": f["message"] + "; requires human review."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f["path"], safe="/")},
                        "region": {"startLine": f["line"]}}}]} for f in report.get("findings", [])]}]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Local directory to review")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=("high", "medium", "none"), default="high")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    try:
        report = scan(args.path)
    except (OSError, ValueError, RecursionError):
        if args.format in {"json", "sarif"}:
            error = {"error": "Unable to scan target directory", "incomplete": True}
            print(json.dumps(to_sarif(error) if args.format == "sarif" else error))
        else:
            print("Unable to scan target directory", file=sys.stderr)
        return 2
    if args.format in {"json", "sarif"}:
        print(json.dumps(to_sarif(report) if args.format == "sarif" else report, ensure_ascii=True, indent=2))
    else:
        for item in report["findings"]:
            # JSON escaping prevents control characters in filenames reaching terminals.
            name = json.dumps(item["path"], ensure_ascii=True)
            print(f'{name}:{item["line"]} {item["severity"]} {item["rule"]} {item["message"]}')
        print(f'{report["files_scanned"]} files scanned; {len(report["findings"])} review hints; '
              f'{len(report["skipped"])} skipped; {report["excluded_entries"]} excluded entries.')
        if report["incomplete"]:
            print("Incomplete scan. Use --format json for skipped paths and reasons.")
        print("Heuristic results require review. No findings does not establish safety.")
    if report["incomplete"]:
        return 2
    fail = {"none": set(), "high": {"high"}, "medium": {"high", "medium"}}[args.fail_on]
    return 1 if any(item["severity"] in fail for item in report["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
