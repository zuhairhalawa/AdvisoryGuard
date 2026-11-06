# AdvisoryGuard v0.3.0

Better findings for version edits, based on running the tool on real advisory edits. There is no new command or option. Without an allow list, this release did not change the exit code on any real edit tested. It changes finding codes and allow-list coverage, so check the table below if a script uses `--allow`.

## Who should update

Anyone who reviews edits to version ranges or multi-package advisories, or who publishes npm advisories. Nothing here fixes a security problem in the tool itself, so there is no urgency if the findings do not matter to you.

## New findings

| Code | Level | When it appears |
| --- | --- | --- |
| `sibling-package-unchanged` | review | A range end changed for one package but not for another in the same advisory that had the same version data. Packages often share a fix, so it asks whether one was left out. A changed start does not count, because packages can have different histories. |
| `known-range-converted` | review | `last_known_affected_version_range` was replaced by a range's one new end. This was an added event and a removed field. It now says whether the two name the same end, comparing strings only. |
| `known-range-removed` | review | That note was removed while the ranges still have an end. This was `field-removed`, with wording that suggested an accident. It now says whether the end also changed. With no end left, it stays `field-removed`. |
| `version-spelling-changed` | review | A range value changed only in leading zeros, such as `2025.08.14` to `2025.8.14`. |
| `version-leading-zero` | warning | `validate` found a leading zero in a range event of an `npm` package or a `SEMVER` range. Semantic versions do not allow these. The file is still valid OSV, so `validate` still exits 0. |

## Behaviour changes to check

| Change | Who it affects |
| --- | --- |
| `--allow range-event-added,field-removed` no longer covers a known range replaced by an end. Use `known-range-converted`. | Scripts with an allow list |
| `--allow field-removed` no longer covers a known range removed while an end remains. Use `known-range-removed`. | Scripts with an allow list |
| `--allow range-event-changed` no longer covers a change only in leading zeros. Use `version-spelling-changed`. | Scripts with an allow list |
| An edit that passed with an allow list now also needs `sibling-package-unchanged` if it leaves out a package that had the same version data. | Scripts with an allow list |
| `validate` prints a new warning for leading zeros in `npm` and `SEMVER` versions. The exit code does not change. | Anyone reading `validate` output |

## How it was tested on real edits

Each row compares this release with 0.2.0 on real before and after files. No exit code changed, and nothing crashed.

| Edits | Count | Left-out package | Known range replaced | Known range removed | Spelling |
| --- | --- | --- | --- | --- | --- |
| The maintainer's own advisory pull requests | 106 | 2 | 6 | 0 | 3 |
| Public edits used while building these checks | 96 | 0 | 2 | 40 | 0 |
| Older public edits not used for anything else | 35 | 0 | 0 | 5 | 0 |

What this does and does not show:

- **Left-out packages:** the two findings are in the maintainer's own pull requests, which the check was designed from. In both, the project's own advisory lists the left-out packages as patched, but those versions are not on Maven Central, so reviewers may decide differently. The older 35 edits included 7 multi-package edits where an end changed, and it gave no false alarms on them, but it has not yet caught a problem in anyone else's edit. An earlier version fired on 2 public edits that only changed a start. Both looked intentional, which is why a start no longer counts.
- **Spelling:** the only misspelled versions found were in the maintainer's own pull requests. It has not met one anywhere else, so it is untested on other data. It gave no false warnings there.
- **Known range removed:** this improves the explanation and does not reduce the number of stops. Of the 13 notes removed while the end stayed the same in the first 96 public edits, none named exactly that end, and some differed a lot, such as `< 8.0.0` with `fixed 8.6.40`. Telling these apart needs version comparison, so they still need review.

These samples are small and were not chosen at random.

## Remaining limitations

- The tool does not compare versions or walk commit history, so it cannot tell a harmless `last_affected` to `fixed` conversion from one that changes status.
- It cannot see a risk that depends on a release that does not exist yet. For example, `fixed 26.0.0` would cover a future backport release 25.7.4, and no finding says so.
- `sibling-package-unchanged` only asks a question. Packages can really differ, it does not notice packages whose data already differed before the edit, and a package left behind when another's start changes is not named.
- `known-range-converted` compares strings. It reads `< Y` and `<= Y`, and any other form is reported as not naming the same end, even if it does.
- The leading-zero checks read spelling only and cannot tell whether a version was published. Other ecosystems can allow these spellings, so `validate` says nothing about them there.
- The limits listed in the [0.2.0 release notes](release-notes-v0.2.0.md) still apply. In particular, the matching budget is not a run-time guarantee.
- There has been no outside review.
