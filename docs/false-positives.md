# False Positives

This document records known false positives from the security tools used in this pipeline,
and documents the rationale for each exception.

## Bandit

No active suppressions. All findings must be reviewed.

If a new false positive is identified:
1. Add it here with: rule ID, file, line, reason, date.
2. Add the `# nosec <RULE_ID>  # reason` comment inline in the source.
3. Get a second review before merging the suppression.

## gitleaks

No active allowlist entries. The `.gitleaks.toml` file (if present) documents any
allowed patterns with rationale.

## pip-audit

No active ignores. If a CVE is a false positive (e.g. the vulnerable code path is
not reachable), document it here and open an issue to track resolution.

| CVE | Package | Reason | Added | Expiry |
|-----|---------|--------|-------|--------|
| —   | —       | —      | —     | —      |

## Policy for adding exceptions

1. A finding must be confirmed as a false positive by at least one reviewer.
2. The exception must have an expiry date (maximum 90 days).
3. The exception must reference a ticket or issue.
4. Exceptions are reviewed at each sprint retrospective.
