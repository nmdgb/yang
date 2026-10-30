# Agent Skill Audit

An offline Python CLI that flags review hints in AI agent skills, plugin source,
and accompanying scripts. Python 3.10+; standard library only.

**Status: new project (v0.2.0), not an established project or security certification.**
There are no verified adoption, download, or community-maintenance metrics yet.

[中文说明](README.zh-CN.md) · [Public-corpus evaluation](research/REPORT.md) ·
[Changelog](CHANGELOG.md) · [Source](https://github.com/nmdgb/yang)

## Quick start

From this directory, without installing anything:

```sh
python agent_skill_audit.py examples/benign
python agent_skill_audit.py examples/review-me --format json
python agent_skill_audit.py /path/to/local/skill --fail-on medium
python agent_skill_audit.py /path/to/local/skill --format sarif
python -m unittest discover -s tests -v
```

Optional installation into your own virtual environment: `python -m pip install .`.
Then use `agent-skill-audit /path/to/skill`. This is a local package; no PyPI
publication or download count is claimed.

The deliberately suspicious fixture should return exit code 1. It contains text
for inspection only. Never execute its example commands.

## Why this exists

Installing an agent skill introduces instructions and scripts that may influence
an agent's shell, filesystem, network requests, or credential access. A maintainer
or user reviewing a contribution needs a short list of locations to inspect.
This tool produces that list without importing or running the reviewed code.
It makes no network requests and has no API integration in this version.

## Rules

| ID | Level | Review hint |
| --- | --- | --- |
| ASA001 | High | Remote download piped into a shell |
| ASA002 | High | Selected PowerShell remote / encoded execution patterns |
| ASA003 | High | Recursive deletion |
| ASA004 | Medium | Selected English / Chinese instruction override phrases |
| ASA005 | Medium | Credential names or sensitive file references |
| ASA006 | High | Selected token-shaped strings or private key headers |
| ASA007 | Medium | Selected shell / dynamic evaluation calls |
| ASA008 | Medium | Selected HTTP upload / write patterns |

JSON findings include rule, severity, relative path, line, context kind, and a static explanation.
Matched source text and token values are deliberately omitted. **Filenames are
included and can themselves contain sensitive information.** Inspect reports
before sharing them. Terminal output escapes filenames to prevent control-character
display effects.

Exit codes: `0` = no selected threshold findings within scanned scope; `1` = one
or more threshold findings; `2` = invalid target, error, or incomplete scan.
`--fail-on none` suppresses findings failures, but never an incomplete scan.

## Scope and limitations

- Scans UTF-8 text in the extensions listed in `EXTENSIONS` in the source, including
  Markdown, Python, shell, PowerShell, JavaScript, TypeScript, JSON, YAML, TOML, and `.env`.
- Ignores `.git`, `.venv`, `venv`, `node_modules`, and `__pycache__`. Unsupported
  extensions are excluded. Counts describe visited entries, not every nested file
  in excluded directories. Exclusions are not treated as scan failures.
- Skips symlinks and Windows reparse points, non-regular files, unreadable input,
  non-UTF-8 / binary input, and files over 1 MiB. These skips mark the scan incomplete.
  Stops after 20,000 visited entries. No archive extraction or remote URL scanning.
- Also limits individual lines to 8,192 characters, total bytes read to 32 MiB,
  and reported findings to 10,000. Exceeding these budgets marks the scan incomplete.
  These are workload limits, not a hard operating-system resource sandbox.
- Single-line regular expressions produce false positives (including documentation
  and this tool's own test corpus) and miss obfuscation, multiline payloads,
  most programming-language semantics, and unfamiliar tokens or languages.
- ASA007 deliberately excludes arbitrary member `.exec()` calls (for example,
  regular expressions and SQL) and requires adjacent parentheses for bare `eval()`
  / `exec()`. It can miss whitespace-separated or aliased dynamic execution.
  Selected `child_process.exec` / `childProcess.execSync` calls are still flagged.
- A network or credential reference is not proof of unauthorized activity. The
  reviewer must assess destination, permissions, user intent, and execution context.
- No malware verdict, dependency vulnerability database, dataflow analysis,
  comprehensive prompt-injection detection, automatic fixes, or sandboxing.
- Scan a stable checkout you control. Path checks are not atomic against concurrent
  filesystem changes; use an isolated environment for actively hostile input.
  Directory enumeration and report memory are not hard resource-isolation boundaries.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[ROADMAP.md](ROADMAP.md). The Chinese introduction is in [README.zh-CN.md](README.zh-CN.md).

The CI configuration tests Python 3.10 and 3.12 on Windows and Linux, using pinned
GitHub Actions and read-only job permissions. Synthetic fixtures and public-corpus
scans are engineering evidence, not adoption metrics or confirmed vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).

