# Changelog

## 0.2.0

This release changes finding codes, allow-list coverage and some exit codes. See
`docs/release-notes-v0.2.0.md` for what to check.

Terminal output

- Fixed the text sanitizer: its pattern contained literal `?` characters, so every `?` was printed as
  `\u003f` while bidirectional and zero-width characters passed through unescaped. Line feeds in advisory
  values are now escaped too, so they can no longer start a new output line. Other default-ignorable characters
  (such as U+034F, variation selectors and Hangul fillers) are escaped as well.
- `--json` output now writes the same characters as `\uXXXX` escapes. The parsed values are unchanged; only
  the bytes differ.
- Usage errors now escape file names and arguments.

Findings

- New `range-bound-converted` finding for `last_affected` replaced by `fixed` (or the reverse). These edits
  were reported as separate removed and added events with explanations that could point the wrong way. The
  finding says affected status may change and asks for a check of the release history, or of the repository for
  a GIT range. It lists several values in one range without pairing them, and applies only when both sides have
  the same number of values. The run still requires review, but a `--allow` list naming
  `range-event-removed,range-event-added` no longer covers this case.
- Several values of one kind changing in one range are now reported as removed and added, instead of being
  paired by text order (which could claim that 10.0.0 became 2.0.1). `--allow range-event-changed` no longer
  covers that case.
- Keys that the dedicated comparers do not read, inside an event, severity or reference object that both sides
  have, are now compared like any other field. Removing one needs review; it used to produce no finding and
  exit 0. This includes a non-string value under an event kind.
- Removing a reference entry when another entry keeps its URL now needs review (`reference-removed`). It used to
  be informational, because the URL was still present.
- Event explanations no longer say "open-ended" while another end remains in the range, "ends earlier" when a
  new `fixed` closes a new interval, or that versions between two `fixed` values "change status" for certain.
  Explanations of new `introduced`, `last_affected` and `limit` events now say "may".

Limits

- The scoring work of `affected` entry and range matching is now limited per comparison, and long runs of
  identical items and long lists of removed references no longer take quadratic time. This is not a limit on
  total run time.
- `pairing-limit` findings now also cover range, custom and severity lists over the per-list limit, and their
  counts match the entries reported separately. A notice is given only when the skipped items could have been
  paired.
- `pairing-limit` now needs review instead of being informational, because the comparison is incomplete. Allowing
  the removed and added codes no longer makes such a run pass; `--allow pairing-limit` accepts it explicitly.
- Array order no longer decides a result. Score ties are broken by content instead of position, and the work
  budget is spent in content order. Before this, reordering an array could change a finding's code and, with an
  allow list, the exit code.

Invalid input

- An object as a range `type` or `repo`, and very large numbers of schema errors, now exit 2. They used to stop
  with an internal error (exit 70).

## 0.1.0

Initial release. Published to npm as `advisoryguard@0.1.0` on 2026-10-26.

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
only; it had not run when these local checks were performed.

Post-publication update: the first GitHub Actions CI run has since passed on Ubuntu, macOS and Windows.
