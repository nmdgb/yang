# Security policy and threat model

This prototype is not a security boundary. It reads untrusted source text and
filenames, applies bundled patterns, and writes a report to stdout. It does not
execute targets or contact the network. Only the current prototype is maintained.

Areas to review include path traversal and symlink / junction handling, filesystem
races, pathological input or regex performance, report leakage and terminal control
characters, and third-party changes to rules or the scanner itself. A malicious rule
contribution could hide important findings or introduce expensive matching behavior.

Use a stable checkout and an isolated environment for hostile material. Reading a
tree that another process can mutate is outside the scanner's security guarantees.

After this project has a public GitHub repository, its owner should enable private
vulnerability reporting. Until that channel exists, do not publish sensitive exploit
details or credentials in public issues. Use only a verified private maintainer
contact. No reporting address is claimed for this unpublished prototype.

Future model-based review must treat submitted code and issue text as untrusted data,
remove secrets, limit cost, and require human approval for any resulting code change.
