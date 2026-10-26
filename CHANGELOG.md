# Changelog

## 0.1.0

Initial release.

- `advisoryguard validate <file>`: validates OSV records against the official OpenSSF OSV JSON schema
  (vendored unmodified, release v1.9.2, pinned commit and SHA-256 verified on load), plus extra checks
  (complete CVSS vectors, real calendar timestamps, CWE id format, duplicate JSON keys, `schema_version`,
  GitHub REST/GraphQL objects detected).
- `advisoryguard diff <before> <after>`: semantic comparison that detects deleted/changed CVSS entries
  (v3 and v4 kept distinct), package renames, range/version events, references, aliases, CWE and other
  metadata, ignoring ordering and formatting; `modified` updates are informational.
- Text and JSON output, `--allow`, `--fail-on`, exit codes 0/1/2/3.
- Fully offline: no network code; the packaged CLI is tested with networking blocked.
- Requires Node.js >= 20.

Verification performed for this release (local, Windows x64): typecheck, lint, 313 unit/CLI tests on
Node 24, production build, `npm pack` + install into a fresh project + installed CLI runs (46 checks),
tarball runtime check on Node 20.20, `npm audit` (0 vulnerabilities), a clean-copy rebuild, and validation of a
350-record sample of genuine GitHub advisories (0 errors). Linux and macOS are exercised by the CI workflow
only; it had not run at the time of this release.
