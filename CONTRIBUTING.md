# Contributing

Please submit small, reviewable changes with reproducible examples.

For a proposed detection rule, explain the behavior being flagged, supply a
synthetic positive case and a benign counterexample, and document known blind
spots. Never contribute live credentials or runnable malicious payloads.

Run `python -m unittest discover -s tests -v` before submitting. Keep the scanner
offline and free of third-party runtime dependencies. Do not add code that executes
scanned files. Changes to traversal, report output, regular expressions, and limits
need explicit security review. Avoid nested or ambiguous repetition in patterns.

Generated code and test fixtures require human review. Rule hits must be described
as review hints rather than confirmed vulnerabilities. No PR is merged automatically.
