"""Scan pre-existing public corpus checkouts at pinned commits; never run their code."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_skill_audit as audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    corpus = json.loads(Path(__file__).with_name("corpus.json").read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for source in corpus:
        root = (args.corpus_root / source["directory"]).resolve()
        commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
        if commit != source["commit"] or dirty:
            raise SystemExit("Corpus must be a clean checkout of " + source["commit"])
        report = audit.scan(root)
        report["source"] = source
        (args.output_dir / (source["directory"] + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        summary.append({**source, "scanner_version": audit.VERSION,
            "files_scanned": report["files_scanned"], "findings": len(report["findings"]),
            "by_rule": dict(sorted(Counter(f["rule"] for f in report["findings"]).items())),
            "incomplete": report["incomplete"], "skipped": report["skipped"],
            "bytes_read": report["bytes_read"]})
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
