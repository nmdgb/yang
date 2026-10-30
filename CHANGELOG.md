# Changelog

## 0.2.0 — prepared 2026-10-31

- Narrow ASA007 after real-corpus review found regular-expression and SQL `.exec()`
  calls and prose uses of `eval (...)` misclassified as dynamic execution.
- Add bounded line length, total read bytes, and findings counts; limits report
  incomplete scans rather than silently returning a clean result.
- Add MDX/JSX/TSX coverage, report context labels, SARIF output and an installable CLI.
- Add pinned CI configuration, contribution templates, and reproducible public-corpus evidence.

## 0.1.0 — local prototype prepared 2026-10-30

- Eight review-hint families, text and JSON reports, synthetic fixtures, and tests.

Dates describe actual local work. They do not imply historical public releases.
