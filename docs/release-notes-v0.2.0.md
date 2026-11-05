# AdvisoryGuard v0.2.0

Hardening of report output, range findings and matching limits. There is no new command or option. This release changes finding codes, allow-list coverage and some exit codes, so check the table below if a script depends on them.

## Who should update

Anyone who prints reports for advisories they did not write, or relies on a clean result. The reported problems need a crafted or unusual advisory file, or an edit of a specific shape. None executes code, exposes data or changes a file. The most important fix: removing certain keys from an advisory could give a clean result and exit 0.

## Fixes

**Findings that could be missed**

- Removing a key the comparers did not read, inside an event, severity or reference object that both files have, gave no finding and exit 0. It now needs review.
- A run that hits a matching limit now needs review through a `pairing-limit` finding, because the comparison is incomplete. Allowing the removed and added codes is no longer enough to pass.
- Reordering an array could change a finding's code and, in some shapes, the exit code. Array order no longer decides a result.
- Removing a reference entry while another entry keeps its URL was only informational. It now needs review.

**Terminal output**

- Every `?` in text output was printed as `\u003f`, while bidirectional and zero-width characters passed through unescaped. Both are fixed.
- Line feeds in advisory values can no longer start a new output line.
- Other default-ignorable characters are now escaped, in text output, JSON output and usage errors. JSON still parses to the same values.

**Range findings**

- Replacing `last_affected` with `fixed`, or the reverse, is now one finding, `range-bound-converted`. It explains the inclusive and exclusive ends and asks you to check the release history. Whether any release changes status depends on what was released, and the tool does not compare versions.
- Several values of one kind changing in a range are no longer paired by text order, which could claim 10.0.0 became 2.0.1.
- Several explanations that stated something the tool cannot know now use "may", or apply only when they are true.

**Limits and invalid input**

- Scoring work for `affected` entries and their ranges now has a limit per comparison.
- Long runs of identical items and long lists of removed references no longer take quadratic time.
- Two kinds of invalid input stopped with an internal error (exit 70). They now exit 2.

## Behaviour changes to check

| Change | Who it affects |
| --- | --- |
| `--allow range-event-removed,range-event-added` no longer covers a conversion. Use `range-bound-converted`. | Scripts with an allow list |
| `--allow range-event-changed` no longer covers several values of one kind changing in a range. They are reported as removed and added. | Scripts with an allow list |
| `pairing-limit` needs review. A run that hit a limit exits 1 unless `pairing-limit` is allowed along with the codes it affects. Lists whose items can never pair, such as lists of strings, give no such finding. | Scripts with an allow list, very large files |
| Removing a key the comparers did not read now exits 1 instead of 0. | Records with extra keys |
| Removing a reference entry while another entry keeps its URL now exits 1 instead of 0. | Records listing one URL under several types |
| `range-bound-converted` applies only when both sides have the same number of values. Otherwise the events are reported as removed and added. | Scripts with an allow list |
| On `range-bound-converted`, `before` and `after` are strings for one value and arrays for several. | JSON consumers |
| `--json` bytes now use `\uXXXX` for unsafe characters. Parsed values are unchanged. | Anyone comparing raw bytes |
| ZWJ, ZWNJ, soft hyphens and variation selectors show as escapes in reports, including legitimate Persian text and joined emoji. Only the display changes. | Readers of those scripts |

## Remaining limitations

**What the matching-work budget bounds:** 20 million units of scoring per comparison, in the heuristic phase of pairing, for `affected` entries and the ranges of paired entries. One unit is one scored pair plus the size of the pair's smaller token set.

**What it does not bound:** parsing, validation, exact matching, canonicalization, token extraction, sorting, and every other comparer. Custom list fields, severity lists and the other keys of objects have only the per-list limit of 250,000 candidates. **It is not a run-time guarantee.** A crafted custom list of about 1.5 MB took over a minute in one local measurement, and a file near the 25 MB limit can take far longer.

Also:

- The tool does not compare versions or walk commit history, so a conversion finding cannot say whether any release changes status.
- If the value that identifies an item changes (an event value, severity type or URL), the item's own finding is reported and a key dropped from it is not named.
- A package or custom field name long enough to make the report larger than Node can hold as one string stops the run with an internal error (exit 70). It never gives a pass.
- When changed ranges share no value, the tool cannot know which became which, so a report can pair them differently from the edit you made. Every changed value is still listed.
- A value that literally contains the text `\u200b` can look the same as the real character in text output. JSON output tells them apart.
- Lookalike letters from other alphabets are not detected.
- Tests check output bytes, not how any terminal draws them.
