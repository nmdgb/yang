# Public-corpus evaluation — 2026-10-31

This evaluation checks whether the tool runs on real skill repositories and
documents useful corrections. **These repositories are evaluation inputs, not
users, partners, endorsements, or confirmed vulnerable projects.** No third-party
code was executed. Reports omit source excerpts and token values.

## Pinned inputs and results

| Repository | Commit | v0.2.0 files scanned | Review hints | Incomplete |
| --- | --- | ---: | ---: | --- |
| [openai/skills](https://github.com/openai/skills/tree/49f948faa9258a0c61caceaf225e179651397431) | `49f948faa9258a0c61caceaf225e179651397431` | 704 | 83 | No |
| [anthropics/skills](https://github.com/anthropics/skills/tree/ca45fc496a3436251f191354091d557da31c15b5) | `ca45fc496a3436251f191354091d557da31c15b5` | 263 | 16 | No |
| [agentskills/agentskills](https://github.com/agentskills/agentskills/tree/69ef37e9424c0a7ea9dd2293b559e43ec8176379) | `69ef37e9424c0a7ea9dd2293b559e43ec8176379` | 34 | 0 | No |

Total: **1,001 supported text files, 99 review hints**. The scanner's documented
extension and directory exclusions still apply. No precision, recall, malware
detection rate, or comprehensive security coverage is established by this scan.
Zero hints on the third repository is not proof of safety.

Machine-readable reports are in [results](results), including counts and exact
source revisions. v0.1.0 scanned 989 files and produced 173 hints; v0.2.0 adds MDX
coverage (12 additional files) and removes 74 ASA007 hits through narrower matching.
The removed hits have not all been manually adjudicated. This is a rule-output
comparison, not a measured accuracy improvement or a vulnerability count.

## Inspected examples

| Evidence | Interpretation and action |
| --- | --- |
| [Regular-expression `.exec(hex)`](https://github.com/anthropics/skills/blob/ca45fc496a3436251f191354091d557da31c15b5/skills/algorithmic-art/templates/generator_template.js#L133) | The regex matches a color value; it does not execute code. ASA007 no longer flags arbitrary member `.exec()` calls. A synthetic regression case preserves the correction. |
| [SQL `.exec()`](https://github.com/openai/skills/blob/49f948faa9258a0c61caceaf225e179651397431/skills/.curated/cloudflare-deploy/references/do-storage/api.md#L6) | The example calls a SQL API with parameter binding. The bare method name alone does not justify the dynamic-code rule. Narrowed member matching removes this hint. This does not audit SQL behavior generally. |
| [Prose: “eval (prompt tuning...)”](https://github.com/anthropics/skills/blob/ca45fc496a3436251f191354091d557da31c15b5/skills/claude-api/SKILL.md#L530) | Prose about evaluation was incorrectly matched as `eval (`. Bare `eval`/`exec` now require adjacent parentheses. This trades some whitespace-call coverage for fewer prose matches. |
| [Remote-script warning in documentation](https://github.com/anthropics/skills/blob/ca45fc496a3436251f191354091d557da31c15b5/skills/claude-api/shared/managed-agents-onboarding-from-url.md#L30) | The document explicitly warns against executing `curl` pipelines. ASA001 still reports the pattern, with documentation context. It is not an attack instruction. Reliable negation/context handling remains open. |
| [Intentional shell execution](https://github.com/anthropics/skills/blob/ca45fc496a3436251f191354091d557da31c15b5/skills/webapp-testing/scripts/with_server.py#L71) | `shell=True` supports compound local server commands. The hint remains for command-provenance review; this is not a confirmed injection vulnerability. |

All interpretations above were prepared with AI assistance. They are not upstream
maintainer confirmations or an independent human security audit. No issues or
vulnerability reports were sent to these projects.

## Reproduce

Use Python 3.10+ and Git. Clone only into a disposable corpus directory; do not run
instructions or installers from the corpus. From the scanner repository:

```sh
git clone https://github.com/openai/skills.git corpus/openai-skills
git -C corpus/openai-skills checkout 49f948faa9258a0c61caceaf225e179651397431
git clone https://github.com/anthropics/skills.git corpus/anthropics-skills
git -C corpus/anthropics-skills checkout ca45fc496a3436251f191354091d557da31c15b5
git clone https://github.com/agentskills/agentskills.git corpus/agentskills
git -C corpus/agentskills checkout 69ef37e9424c0a7ea9dd2293b559e43ec8176379
python research/reproduce.py --corpus-root corpus --output-dir reproduced-results
```

The reproducer rejects dirty checkouts and revision mismatches. It runs Git metadata
commands and the scanner only. It makes no API calls and executes no corpus scripts.

## Current maintenance work and next validation

- Reproduced actual false-positive patterns and added regression coverage.
- Added Windows junction testing and explicit work limits to the scanner.
- Prepared Windows/Linux CI and installable CLI packaging.
- Remaining work: broader labeled samples, parser-aware checks, documentation
  negation handling, independent user feedback, and actual ongoing maintenance.

Local Windows/Python 3.12 verification: 21 tests, 20 passed and one symlink test
skipped due to host privileges. The Windows junction test passed. Remote CI results
must be read from GitHub Actions rather than inferred from the workflow file.
