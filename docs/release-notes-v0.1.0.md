# AdvisoryGuard v0.1.0

First release. A small, offline CLI that catches accidental data loss and risky metadata changes
when you edit a GitHub Security Advisory / OSV record - motivated by a real incident where fixing a
package name through the web UI silently deleted the advisory's CVSS vector.

## Highlights

- `advisoryguard diff before.json after.json` compares two OSV records semantically (ignoring key
  order, array order and formatting) and reports deleted or changed CVSS v3/v4 entries, package
  renames, changed `introduced` / `fixed` / `last_affected` events, removed references, aliases and
  CWEs, withdrawals, and any other field that disappeared. Every finding that needs review says why.
  `modified` timestamp updates are informational.
- `advisoryguard validate advisory.json` validates against the **official OpenSSF OSV schema**
  (v1.9.2, vendored unmodified, pinned to commit `c8a57bd` and hash-checked), with a few extra checks.
- Text or `--json` output, `--allow` to acknowledge intended changes, `--fail-on`, and CI-friendly exit
  codes: `0` ok, `1` needs review, `2` invalid advisory, `3` usage/IO error.
- No network access, no telemetry, never modifies input files. One runtime dependency (`ajv`).

## Install

```sh
npm install --global advisoryguard      # Node.js >= 20
advisoryguard diff before.json after.json
```

## What was verified

- 313 automated tests (unit, CLI, and 11 unmodified genuine GitHub advisories), type-check, lint, build.
- The packed tarball installed into a fresh project and run via both the npm shim and the entry file,
  with all network access blocked, plus a run of the tarball on Node 20.
- A sample of 350 genuine GitHub advisories validates with zero errors; mutation checks over the same
  sample (deleted CVSS, renamed package, removed fixed event, dropped reference/alias/CWE, corrupted
  fields) produced no missed detections and no false alarms on reordered or `modified`-only edits.
- `npm audit`: 0 known vulnerabilities.

## Known limitations

- Validates every record against one schema version (OSV v1.9.2) regardless of its `schema_version`.
- Cannot check that a renamed package exists in a registry (deliberately offline). Rename detection is a
  heuristic; unrelated package replacements are still reported for review.
- CVSS v4 scores are not computed (v4 vectors are validated and compared metric by metric).
- Validation uses Ajv only. Linux/macOS are covered by CI configuration; this release was developed and
  tested locally on Windows.

See the README for details. Third-party notices: OSV schema (Apache-2.0), test data (CC BY 4.0).
