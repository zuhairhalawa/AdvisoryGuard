# Changelog

## Unreleased

This changes finding codes and allow-list coverage. The cases come from running the tool on real advisory edits.

- New `sibling-package-unchanged` finding: version ranges changed for one package but not for another in the same
  advisory that had the same version data. It needs review, because packages often share a fix but can really
  differ. A `--allow` list that used to pass such an edit now also has to name this code.
- New `known-range-converted` finding: `last_known_affected_version_range` replaced by a range's one new end. This
  was reported as an added event and a removed field, and the second suggested the value may have been dropped by
  accident. The finding says whether the two name the same end, comparing strings only. A `--allow` list naming
  `range-event-added,field-removed` no longer covers this case.
- New `known-range-removed` finding: `last_known_affected_version_range` removed while the ranges still have an
  end. This was `field-removed`, which suggested the value may have been dropped by accident, although the end
  had usually moved too. It still needs review, and it says whether the end also changed. With no end left it
  stays `field-removed`. `--allow field-removed` no longer covers this case.
- New `version-spelling-changed` finding: a range value that changes only in leading zeros, such as `2025.08.14` to
  `2025.8.14`. `--allow range-event-changed` no longer covers this case.
- New `version-leading-zero` warning from `validate`, for range events in `npm` packages and `SEMVER` ranges. The
  file is still valid OSV, so `validate` still exits 0.

## 0.2.0

This release changes finding codes, allow-list coverage and some exit codes. See the
[release notes](https://github.com/zuhairhalawa/AdvisoryGuard/blob/main/docs/release-notes-v0.2.0.md) for what to
check.

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
  counts match the entries reported separately. Lists of non-objects, such as strings, give no such finding.
- `pairing-limit` now needs review instead of being informational, because the comparison is incomplete. Allowing
  the removed and added codes no longer makes such a run pass; `--allow pairing-limit` accepts it explicitly.
- Array order no longer decides a result. Score ties are broken by content instead of position, and the work
  budget is spent in content order. Before this, reordering an array could change a finding's code and the exit
  code.

Invalid input

- An object as a range `type` or `repo`, and very large numbers of schema errors, now exit 2. They used to stop
  with an internal error (exit 70).

Verification for this release: typecheck, lint and all tests on Ubuntu, macOS and Windows with Node 22 and 24 in
CI, and on Windows with Node 24 locally; the packed tarball on Node 20 on the same three systems in CI; `npm audit`
with no known vulnerabilities; and the vendored schema check.

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
