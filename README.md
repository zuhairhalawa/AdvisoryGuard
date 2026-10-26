# AdvisoryGuard

Catch accidental data loss and risky metadata changes **before** you submit an edit to a
[GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories) /
[OSV](https://ossf.github.io/osv-schema/) record.

AdvisoryGuard exists because of a real class of mistake: correcting a **package name** in an
advisory through the web UI silently removed the advisory's **CVSS severity vector**. Nothing
warned the editor. AdvisoryGuard compares the advisory JSON before and after your edit and tells
you exactly what disappeared, what changed, and why it deserves a second look.

- Offline. The CLI has no network code at all (no telemetry, no API keys); the packaged CLI is
  tested with networking blocked. Free to run.
- Never modifies your files. Never executes anything found in advisory content.
- Validates against the **official OpenSSF OSV JSON schema** (vendored, pinned and hash-checked).
- Pure Node.js (>= 20, no native code), one runtime dependency (`ajv`).

> **Status:** v0.1.0, first release. If `npm install advisoryguard` does not find the package yet,
> it has not been published; install from source or a packed tarball (see [Install](#install)).

## Quick demo

`regression-before.json` is an advisory with CVSS v3 + v4 and two packages. In
`regression-after-bug.json` the npm package name was fixed (`@acme/parsr` -> `@acme/parser`),
and the CVSS entries were lost in the process:

```text
$ advisoryguard diff regression-before.json regression-after-bug.json
AdvisoryGuard diff
  before: test/fixtures/regression-before.json
  after:  test/fixtures/regression-after-bug.json
  id:     GHSA-4xq9-w7rh-c3p2

Validation of test/fixtures/regression-after-bug.json

WARNING no-severity  severity
  No CVSS severity is present. If this advisory previously had one, make sure it was not dropped by an edit.

Changes

REVIEW  severity-removed  severity[CVSS_V3]
  CVSS_V3 severity was removed: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (base score 9.8, Critical).
  Why: A CVSS entry is what scanners and Dependabot use to rate this advisory. Editing an unrelated field (such as a package name) should never delete it. If the removal is not intentional, restore the entry.

REVIEW  severity-removed  severity[CVSS_V4]
  CVSS_V4 severity was removed: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N.
  Why: A CVSS entry is what scanners and Dependabot use to rate this advisory. Editing an unrelated field (such as a package name) should never delete it. If the removal is not intentional, restore the entry.

REVIEW  package-renamed  affected[npm/@acme/parser].package.name
  Package name changed from "@acme/parsr" to "@acme/parser" (npm).
  Why: The advisory now flags a different package. Correcting a typo is normal, but verify the new name exists in the registry, and that the severity, version ranges and references were left untouched by the edit.

INFO    modified-updated  modified
  modified timestamp updated: 2026-03-02T10:15:30Z -> 2026-03-05T14:00:00Z. This is expected for any edit and is not a vulnerability change.

REVIEW REQUIRED (3 changes need review, 1 informational)
$ echo $?
1
```

With a correct edit (same rename, severity intact, even if a tool reordered every key and array)
you only get the rename to confirm:

```text
REVIEW  package-renamed  affected[npm/@acme/parser].package.name
  Package name changed from "@acme/parsr" to "@acme/parser" (npm).
INFO    modified-updated  modified
REVIEW REQUIRED (1 change needs review, 1 informational)
```

## Install

Requires Node.js 20 or newer.

From npm (once published):

```sh
npm install --global advisoryguard
advisoryguard --help
# or without installing
npx advisoryguard diff before.json after.json
```

From source (works today):

```sh
git clone https://github.com/zuhairhalawa/AdvisoryGuard.git
cd AdvisoryGuard
npm ci
npm run build
npm pack                       # creates advisoryguard-0.1.0.tgz
npm install --global ./advisoryguard-0.1.0.tgz
```

## Usage

```sh
advisoryguard validate advisory.json
advisoryguard diff before.json after.json
```

Getting `before.json`: you need the advisory in **OSV JSON** format (not the REST/GraphQL object).
Download it from the [GitHub Advisory Database](https://github.com/github/advisory-database)
(`advisories/github-reviewed/YYYY/MM/GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json`) or from
`https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx`, keep a copy, edit another copy, and diff the two.

| Option | Meaning |
| --- | --- |
| `-f, --format text\|json`, `--json` | Output format (default `text`). |
| `--allow code1,code2` | Acknowledge intended review findings (e.g. `package-renamed`). They are still listed as `ALLOWED` but no longer fail the run. Never hides invalid data. |
| `--fail-on review\|invalid` | `diff` only. `review` (default) exits 1 on review findings; `invalid` only fails for invalid data. |
| `--no-color` | Disable color (also honors `NO_COLOR`; `FORCE_COLOR` forces it). |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Valid / nothing that requires review (informational findings only). |
| 1 | `diff`: changes that require human review. |
| 2 | Invalid advisory data: malformed JSON, OSV schema violations, bad CVSS vectors, unsupported `schema_version` (for `diff`: the *edited* advisory is invalid). |
| 3 | Usage error or unreadable file. |

### CI example

```yaml
- run: npx advisoryguard diff advisories/before.json advisories/after.json --allow package-renamed
```

### JSON output

`--json` prints a stable object (`outputSchemaVersion: 1`) with `status` (`clean|review|invalid`),
`summary`, `findings[]` (`code`, `level`, `path`, `message`, `why`, `before`, `after`),
per-document `validation`, and `exitCode`.

## What it checks

**validate** - checks the record against the official OSV schema
([`ossf/osv-schema`](https://github.com/ossf/osv-schema) `validation/schema.json`, release **v1.9.2**,
commit `c8a57bd`, Apache-2.0, vendored unmodified in `vendor/osv-schema/`). That means, among other
things: required `id`/`modified`; `id` must carry a registered database prefix (`GHSA-`, `CVE-`, ...);
`affected[].package.ecosystem` must be a listed ecosystem (case-sensitive); range events must have
exactly one key, include `introduced`, and not combine `fixed` with `last_affected`; GIT ranges need a
`repo` and full commit hashes; severity vectors must match the CVSS v2/v3/v4 syntax of their `type`;
`affected[].severity` is not allowed when top-level `severity` exists; unknown **top-level** fields are
rejected (custom data belongs in `database_specific`).

On top of the schema it adds a few checks, each reported with its own code:

- CVSS vectors must also contain all mandatory base metrics (the schema's regex accepts partial vectors);
- timestamps must be real calendar dates (`2026-02-31T00:00:00Z` matches the schema's pattern but is not a date);
- `database_specific.cwe_ids` entries must look like `CWE-79`;
- duplicate keys in the JSON text (which `JSON.parse` would silently collapse), and unsupported / newer `schema_version`;
- GitHub REST/GraphQL advisory objects (not OSV) are recognised and rejected with a pointer to the OSV format.

Problems are `error` (invalid, exit 2) or `warning` (valid but unusual: missing severity, duplicate
references, scheme-less URLs, non-semver versions in a SEMVER range, ...). JSON Schema
`format` keywords (`uri`, `date-time`) are treated as annotations, as in the specification's default
mode, so a genuine GitHub record with a scheme-less reference URL is valid with a warning.

**diff** - semantic comparison, independent of key order, array order and formatting:

| Area | Behavior |
| --- | --- |
| `severity[]` (also `affected[].severity`) | Matched by type, so CVSS v3 and v4 (and several entries) stay distinct. Removed = review, changed = review (with metric delta and v3 base score), added = info. |
| `affected[]` | Matched by ecosystem+name; a lone unmatched package in the same ecosystem is treated as a **rename** so its ranges/severity are still compared. Removed/added packages = review. |
| ranges / events | `introduced`, `fixed`, `last_affected`, `limit` added/removed/changed = review, with an explanation (e.g. a removed `fixed` leaves the range open-ended). Explicit `versions[]` additions/removals = review. |
| references, aliases, related, upstream | Removal = review (lost provenance / cross-references); addition = info. URLs compared ignoring trailing slash and host case. |
| CWE (`database_specific.cwe_ids`), GitHub severity label | Removal/change = review; addition = info. |
| `id`, `published`, `withdrawn` | Changes = review (withdrawing is flagged). |
| `modified` | Updated = **info** (expected). Moving backwards or deleting = review. |
| `summary` / `details` | Wording edits = info. Emptied = review. `details` shrinking below half of its length (if >= 200 chars) = review (heuristic). |
| Everything else | Generic structural diff: a removed field/list item is **never silent** (review); additions and most value changes are info; changed values of fields whose name contains severity/cwe/cve/fix/patch/affect/version/range/score are review. |

A change is never declared "wrong" - `review` means "a human should confirm this was intended",
and every such finding says why.

## Limitations (please read)

- **One schema version.** Every record is validated against the single bundled schema (OSV
  v1.9.2), whatever `schema_version` it declares. It does not track upstream automatically; update
  with `npm run update:schema -- <tag>` and re-run the tests. `npm run verify:schema` (needs network)
  proves the vendored file is byte-identical to upstream at the pinned commit.
- **One schema engine.** Validation uses Ajv only; the schema was not cross-checked with a second
  JSON Schema implementation. Ajv's raw oneOf/if-then errors are translated into plainer messages.
- **Tested on real data, not exhaustively.** The test suite includes 11 unmodified GitHub advisories
  (`test/fixtures/real/`), and the release was also checked against a sample of 350 genuine records
  (reviewed and unreviewed, 2019-2026, taken from the start of six month directories, so not a random
  sample): all validated without errors. It has not been run against the whole database.
- **No registry verification.** AdvisoryGuard cannot tell you whether `@acme/parser` exists on
  npm. It flags renames and asks you to check. Registry lookups are deliberately not implemented
  (the tool is offline by design).
- **CVSS v4 scores are not computed**, only v4 vectors are validated and compared metric by metric.
  v3.x base scores are computed from the base metrics (temporal/environmental metrics ignored).
- Rename detection is heuristic: when exactly one unmatched affected entry per ecosystem remains
  on each side it is treated as the same entry. A genuine "replace package A with unrelated package B"
  edit looks the same and is still reported as review.
- The comparison treats every JSON array as unordered, which is right for advisories but would be
  wrong for order-sensitive data in custom extension fields.
- Matching of unmatched `affected` entries (the rename heuristic) is bounded to 250,000 candidate
  comparisons so that a huge crafted file cannot make the tool hang. Beyond that limit the entries are
  reported as removed/added (still "needs review") together with a `pairing-limit` notice.
- It compares two files you provide; it does not fetch advisories or talk to GitHub.
- A newer OSV schema may allow things this version rejects (for example a new ecosystem); you would
  see an `unknown-ecosystem`-style error until the vendored schema is updated.

## Security notes

Input is parsed with `JSON.parse` only (no `eval`, no code or command execution from advisory
content), is size-limited (25 MB) and depth-limited, and control characters in advisory text are
escaped before being printed to a terminal. Files are opened read-only. The shipped source contains
no network, child-process or dynamic-code APIs, and `npm run verify:pack` runs the installed CLI with
all network access blocked to confirm it. `npm audit` reports no known vulnerabilities at release time.
This is a review aid, not a security boundary: it cannot decide whether an advisory is *correct*.

## Platforms

Pure JavaScript, so there is nothing platform-specific to compile. The GitHub Actions workflow runs the
full pipeline on Ubuntu, macOS and Windows with Node 22 and 24, and installs the packed tarball on Node 20
(the minimum supported version) on the same three systems. See `CHANGELOG.md` for what has been
verified for each release.

## Development

```sh
npm ci
npm run check         # typecheck + lint + tests + build (needs Node >= 22.12 for the test runner)
npm run verify:pack   # pack, install into a fresh temp project, run the installed CLI offline
npm run verify:schema # (network) vendored OSV schema == upstream at the pinned commit
```

Third-party material: see `THIRD_PARTY_NOTICES.md` (OSV schema: Apache-2.0; test data: CC BY 4.0).

## License

MIT (c) zuhairhalawa
