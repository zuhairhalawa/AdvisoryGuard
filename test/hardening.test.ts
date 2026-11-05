// This file is ASCII-only. Invisible and right-to-left characters are written as escapes so a
// reader can see what each case contains and re-encoding the file cannot change them.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { run } from "../src/cli/main.js";
import type { CliIo } from "../src/cli/main.js";
import { diffAffected } from "../src/core/diff/affected.js";
import { diffReferences } from "../src/core/diff/fields.js";
import { diffSeverity } from "../src/core/diff/severity.js";
import { MAX_MATCHING_WORK, MAX_PAIR_CANDIDATES, overlap, pairItems } from "../src/core/pairing.js";
import type { WorkBudget } from "../src/core/pairing.js";
import type { Finding, JsonObject } from "../src/core/types.js";
import { canonical, sanitizeForTerminal, stringifyForTerminal } from "../src/core/util.js";
import { diffAdvisories, validateText } from "../src/index.js";
import { createStyle } from "../src/report/style.js";
import { renderDiff, renderValidate } from "../src/report/text.js";
import { codes, diff, reviewCodes } from "./helpers.js";

const tmp = mkdtempSync(join(tmpdir(), "advisoryguard-hardening-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const BS = String.fromCharCode(92);

function doc(events: JsonObject[], overrides: Record<string, unknown> = {}): JsonObject {
  return {
    schema_version: "1.4.0",
    id: "GHSA-2222-3333-4444",
    modified: "2026-01-01T00:00:00Z",
    published: "2026-01-01T00:00:00Z",
    summary: "Synthetic advisory",
    details: "Synthetic advisory used for local regression tests.",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" }],
    affected: [{ package: { ecosystem: "npm", name: "@acme/parser" }, ranges: [{ type: "ECOSYSTEM", events }] }],
    references: [{ type: "WEB", url: "https://example.test/advisory" }],
    ...overrides,
  } as JsonObject;
}

function cliDiff(before: JsonObject, after: JsonObject, extraArgs: string[] = []): { code: number; out: string } {
  const b = join(tmp, "before.json");
  const a = join(tmp, "after.json");
  writeFileSync(b, JSON.stringify(before));
  writeFileSync(a, JSON.stringify(after));
  let out = "";
  const io: CliIo = { stdout: { write: (s: string) => ((out += s), true) }, stderr: { write: () => true }, env: {} };
  return { code: run(["diff", b, a, ...extraArgs], io), out };
}

const LAST_AFFECTED: JsonObject[] = [{ introduced: "0" }, { last_affected: "22.0.4" }];
const FIXED: JsonObject[] = [{ introduced: "0" }, { fixed: "23.0.0" }];

describe("sanitizeForTerminal", () => {
  it.each([
    ["line feed", "a\nb", `a${BS}u000ab`],
    ["escape", "a\u001bb", `a${BS}u001bb`],
    ["right-to-left override", "a\u202eb", `a${BS}u202eb`],
    ["bidi isolate", "a\u2066b", `a${BS}u2066b`],
    ["zero-width space", "a\u200bb", `a${BS}u200bb`],
    ["right-to-left mark", "a\u200fb", `a${BS}u200fb`],
    ["byte order mark", "a\ufeffb", `a${BS}ufeffb`],
    ["line separator", "a\u2028b", `a${BS}u2028b`],
    ["paragraph separator", "a\u2029b", `a${BS}u2029b`],
    ["astral format character", "a\u{E0041}b", `a${BS}u{e0041}b`],
  ])("escapes %s", (_name, input, want) => {
    expect(sanitizeForTerminal(input)).toBe(want);
  });

  it.each([
    ["question mark", "why?"],
    ["tab", "a\tb"],
    ["accented Latin", "caf\u00e9"],
    ["Arabic text", "\u0645\u0631\u062d\u0628\u0627"],
    ["emoji", "\u{1F600}"],
  ])("leaves %s unchanged", (_name, input) => {
    expect(sanitizeForTerminal(input)).toBe(input);
  });
});

describe("text report of untrusted advisory values", () => {
  it("prints a reference URL containing a question mark verbatim", () => {
    const before = doc(FIXED, { references: [{ type: "WEB", url: "https://example.test/advisory?id=1" }] });
    const r = cliDiff(before, doc(FIXED));
    expect(r.out).toContain("https://example.test/advisory?id=1");
  });

  it("prints the ecosystem hint with its question mark", () => {
    const after = doc(FIXED);
    (after["affected"] as any)[0].package.ecosystem = "NPM";
    const r = cliDiff(doc(FIXED), after);
    expect(r.out).toContain('Did you mean "npm"? (names are case-sensitive)');
  });

  it("never lets a line feed in a package name start a new output line", () => {
    const after = doc(FIXED);
    (after["affected"] as any)[0].package.name = "x\nMARKER";
    const r = cliDiff(doc(FIXED), after);
    expect(r.out.split("\n").filter((l) => l.trimStart().startsWith("MARKER"))).toEqual([]);
    expect(r.out).toContain(`x${BS}u000aMARKER`);
  });

  it("shows bidi and zero-width characters in a renamed package instead of passing them through", () => {
    for (const [ch, shown] of [["\u202e", "u202e"], ["\u200b", "u200b"]] as const) {
      const after = doc(FIXED);
      (after["affected"] as any)[0].package.name = `@acme/par${ch}ser`;
      const r = cliDiff(doc(FIXED), after);
      expect(r.out.includes(ch)).toBe(false);
      expect(r.out).toContain(`@acme/par${BS}${shown}ser`);
    }
  });
});

describe("range end changing kind", () => {
  function onlyConversion(findings: Finding[]): Finding {
    const found = findings.filter((f) => f.code === "range-bound-converted");
    expect(found).toHaveLength(1);
    return found[0] as Finding;
  }

  /** The tool has no release history, so it must not say that any release did or did not change status. */
  function expectNonCommittalExplanation(f: Finding): void {
    expect(f.why).toMatch(/may change which releases are affected, or may change nothing/);
    expect(f.why).toMatch(/"last_affected" is an inclusive end/);
    expect(f.why).toMatch(/"fixed" is an exclusive end/);
    expect(f.why).toMatch(/release history/);
    expect(`${f.message} ${f.why}`).not.toMatch(/change status|open-ended|earlier/);
  }

  it("does not claim a status change when both ends may describe the same releases", () => {
    // If 4.32.1 is the release right after 4.32.0, these two ends describe the same affected set.
    const r = diff(
      doc([{ introduced: "0" }, { last_affected: "4.32.0" }]),
      doc([{ introduced: "0" }, { fixed: "4.32.1" }]),
    );
    expect(reviewCodes(r)).toEqual(["range-bound-converted"]);
    const f = onlyConversion(r.findings);
    expect(f.before).toBe("4.32.0");
    expect(f.after).toBe("4.32.1");
    expectNonCommittalExplanation(f);
  });

  it("describes both ends of a conversion that can widen the affected set, without saying it does", () => {
    // A release such as 22.0.5, if one exists, would move from unaffected to affected.
    const r = diff(doc(LAST_AFFECTED), doc(FIXED));
    expect(reviewCodes(r)).toEqual(["range-bound-converted"]);
    const f = onlyConversion(r.findings);
    expect(f.before).toBe("22.0.4");
    expect(f.after).toBe("23.0.0");
    expect(f.message).toContain("an inclusive end at 22.0.4 became an exclusive end at 23.0.0");
    expectNonCommittalExplanation(f);
  });

  it("reports the reverse conversion and says the patched version is gone", () => {
    const r = diff(doc(FIXED), doc(LAST_AFFECTED));
    expect(reviewCodes(r)).toEqual(["range-bound-converted"]);
    const f = onlyConversion(r.findings);
    expect(f.before).toBe("23.0.0");
    expect(f.after).toBe("22.0.4");
    expect(f.message).toContain("an exclusive end at 23.0.0 became an inclusive end at 22.0.4");
    expect(f.message).toMatch(/no longer names a patched version/);
    expectNonCommittalExplanation(f);
  });

  it("does not say the patched version is gone when another fixed event remains", () => {
    // Mixing both kinds in one range is invalid OSV, but the comparison still has to describe it correctly.
    const r = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { last_affected: "2.5.0" }]),
    );
    expect(r.status).toBe("invalid");
    const f = onlyConversion(r.findings);
    expect(f.message).toContain("an exclusive end at 3.0.0 became an inclusive end at 2.5.0");
    expect(f.message).not.toMatch(/no longer names a patched version/);
  });

  it("lists several converted ends without pairing them, because it does not compare versions", () => {
    // Sorted as text, 10.0.0 comes before 2.0.0, so pairing by position would claim 10.0.0 became 2.0.1.
    const r = diff(
      doc([{ introduced: "0" }, { last_affected: "2.0.0" }, { introduced: "5.0.0" }, { last_affected: "10.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "2.0.1" }, { introduced: "5.0.0" }, { fixed: "9.0.0" }]),
    );
    expect(reviewCodes(r)).toEqual(["range-bound-converted"]);
    const f = onlyConversion(r.findings);
    expect(f.before).toEqual(["10.0.0", "2.0.0"]);
    expect(f.after).toEqual(["2.0.1", "9.0.0"]);
    expect(f.message).toMatch(/not paired/);
    expect(f.message).not.toMatch(/10\.0\.0 was replaced|2\.0\.0 was replaced/);
    expectNonCommittalExplanation(f);
  });

  it("does not call it a conversion when the number of ends changes", () => {
    const r = diff(
      doc([{ introduced: "0" }, { last_affected: "2.0.0" }, { introduced: "5.0.0" }, { last_affected: "6.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "7.0.0" }]),
    );
    expect(codes(r)).not.toContain("range-bound-converted");
    expect(codes(r).sort()).toEqual(["range-event-added", "range-event-removed", "range-event-removed", "range-event-removed"]);
    expect(r.findings.map((x) => x.why ?? "").join(" ")).not.toMatch(/open-ended|ends the vulnerable range earlier/);
  });

  it("does not let the conversion code clear an edit that leaves a later interval without an end", () => {
    const allow = ["range-bound-converted"];
    const before = doc([{ introduced: "0" }, { last_affected: "1.0.0" }, { introduced: "2.0.0" }, { last_affected: "3.0.0" }]);
    const after = doc([{ introduced: "0" }, { fixed: "9.0.0" }, { introduced: "2.0.0" }]);
    expect(validateText(JSON.stringify(after)).valid).toBe(true);
    expect(diff(before, after, allow).status).toBe("review");
    expect(cliDiff(before, after, ["--allow", "range-bound-converted"]).code).toBe(1);
    const reverse = doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]);
    const toOne = doc([{ introduced: "0" }, { last_affected: "9.0.0" }, { introduced: "2.0.0" }]);
    expect(diff(reverse, toOne, allow).status).toBe("review");
  });

  it("still needs review unless the conversion code is explicitly allowed", () => {
    expect(diff(doc(LAST_AFFECTED), doc(FIXED)).status).toBe("review");
    const allowed = diff(doc(LAST_AFFECTED), doc(FIXED), ["range-bound-converted"]);
    expect(allowed.status).toBe("clean");
    expect(allowed.acknowledged).toBe(1);
    expect(diff(doc(LAST_AFFECTED), doc(FIXED), ["range-event-removed", "range-event-added"]).status).toBe("review");
    expect(cliDiff(doc(LAST_AFFECTED), doc(FIXED)).code).toBe(1);
    expect(cliDiff(doc(LAST_AFFECTED), doc(FIXED), ["--allow", "range-bound-converted"]).code).toBe(0);
  });

  it("does not treat a plain removal or a same-kind change as a conversion", () => {
    const removed = diff(doc(FIXED), doc([{ introduced: "0" }]));
    expect(codes(removed)).toEqual(["range-event-removed"]);
    const changed = diff(doc(FIXED), doc([{ introduced: "0" }, { fixed: "24.0.0" }]));
    expect(codes(changed)).toEqual(["range-event-changed"]);
  });

  it("rejects fixed and last_affected in one range as invalid, whatever else the comparison lists", () => {
    // OSV forbids both kinds in one range. This fixture exists to check the verdict, not to model a real edit.
    const mixed = doc([{ introduced: "0" }, { last_affected: "22.0.5" }, { fixed: "23.0.0" }]);
    const validation = validateText(JSON.stringify(mixed));
    expect(validation.valid).toBe(false);
    expect(validation.findings.map((f) => f.code)).toContain("range-fixed-and-last-affected");

    const r = diff(doc(LAST_AFFECTED), mixed);
    expect(r.before.valid).toBe(true);
    expect(r.after.valid).toBe(false);
    expect(r.status).toBe("invalid");
    // The event changes stay listed so a reviewer can see the edit, but allowing them cannot pass the file.
    expect(codes(r).sort()).toEqual(["range-event-added", "range-event-changed"]);
    expect(diff(doc(LAST_AFFECTED), mixed, ["range-event-added", "range-event-changed"]).status).toBe("invalid");
    expect(cliDiff(doc(LAST_AFFECTED), mixed).code).toBe(2);
  });
});

describe("repeated comparisons of objects the caller changes in between", () => {
  const entry = (name: string, versions: string[]): JsonObject => ({ package: { ecosystem: "npm", name }, versions });

  function renames(): { before: JsonObject; after: JsonObject } {
    return {
      before: doc(FIXED, { affected: [entry("old-a", ["1.0.0", "1.0.1"]), entry("old-b", ["2.0.0", "2.0.1"])] }),
      after: doc(FIXED, { affected: [entry("new-a", ["1.0.0", "1.0.1"]), entry("new-b", ["2.0.0", "2.0.1"])] }),
    };
  }

  function swapVersions(advisory: JsonObject): void {
    const [first, second] = advisory["affected"] as any[];
    [first.versions, second.versions] = [second.versions, first.versions];
  }

  it("pairs renamed entries by their current versions through diffAdvisories", () => {
    const { before, after } = renames();
    const first = diffAdvisories(before, after);
    swapVersions(after);
    const second = diffAdvisories(before, after);
    const fresh = diffAdvisories(structuredClone(before), structuredClone(after));
    expect(second).toEqual(fresh);
    expect(second).not.toEqual(first);
  });

  it("pairs ranges by their current events through diffAdvisories", () => {
    const range = (introduced: string, fixed: string): JsonObject => ({
      type: "ECOSYSTEM",
      events: [{ introduced }, { fixed }],
    });
    const withRanges = (ranges: JsonObject[]): JsonObject =>
      doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, ranges }] });
    const before = withRanges([range("1.0.0", "1.5.0"), range("2.0.0", "2.5.0")]);
    const after = withRanges([range("1.0.0", "1.6.0"), range("2.0.0", "2.6.0")]);
    const first = diffAdvisories(before, after);
    // The first range now resembles the second "before" range and the reverse, with new fixed values.
    const ranges = (after["affected"] as any)[0].ranges;
    ranges[0].events = [{ introduced: "2.0.0" }, { fixed: "2.7.0" }];
    ranges[1].events = [{ introduced: "1.0.0" }, { fixed: "1.7.0" }];
    const second = diffAdvisories(before, after);
    const fresh = diffAdvisories(structuredClone(before), structuredClone(after));
    expect(second).toEqual(fresh);
    expect(second).not.toEqual(first);
  });

  // These entry points parse new objects on every call, so reuse cannot reach them. This guards that
  // property; only the two diffAdvisories tests above can detect caches that outlive a comparison.
  it("gives the same result through the text entry point and the CLI, which parse new objects on every call", () => {
    const { before, after } = renames();
    diff(before, after);
    cliDiff(before, after);
    swapVersions(after);
    expect(diff(before, after)).toEqual(diff(structuredClone(before), structuredClone(after)));
    expect(cliDiff(before, after)).toEqual(cliDiff(structuredClone(before), structuredClone(after)));
  });
});

describe("work budget accounting in pairItems", () => {
  const pair = (budget: WorkBudget, b: string[], a: string[], canon = (s: string): string => s) =>
    pairItems(b, a, canon, (s) => `after:${s}`, () => 1, { budget, weight: () => 1 });

  it("allows exactly the budgeted comparisons", () => {
    const budget = { remaining: 6 };
    const r = pair(budget, ["b0", "b1"], ["a0", "a1", "a2"]);
    expect(r.skipped).toBe(false);
    expect(budget.remaining).toBe(0);
    expect(r.pairs.map((p) => p.exact)).toEqual([false, false]);
  });

  it("skips the phase one unit short and keeps no partial matches", () => {
    const budget = { remaining: 5 };
    const r = pair(budget, ["b0", "b1"], ["a0", "a1", "a2"]);
    expect(r.skipped).toBe(true);
    expect(budget.remaining).toBe(-1);
    expect(r.pairs).toEqual([]);
    expect(r.restB).toEqual([0, 1]);
    expect(r.restA).toEqual([0, 1, 2]);
  });

  it("does not charge exact matches and keeps them when the heuristic phase is skipped", () => {
    const budget = { remaining: 0 };
    const r = pairItems(["same", "b"], ["same", "a"], (s) => s, (s) => s, () => 1, { budget, weight: () => 1 });
    expect(r.skipped).toBe(true);
    expect(budget.remaining).toBe(-1);
    expect(r.pairs).toEqual([{ bi: 0, ai: 0, exact: true }]);
    expect(r.restB).toEqual([1]);
    expect(r.restA).toEqual([1]);

    const untouched = { remaining: 0 };
    const allExact = pairItems(["x", "y"], ["y", "x"], (s) => s, (s) => s, () => 1, { budget: untouched, weight: () => 1 });
    expect(allExact.skipped).toBe(false);
    expect(untouched.remaining).toBe(0);
  });

  it("shares one budget across calls, so a later call skips once it has run out", () => {
    const budget = { remaining: 3 };
    expect(pair(budget, ["b0"], ["a0", "a1", "a2"]).skipped).toBe(false);
    const later = pair(budget, ["b1"], ["a3"]);
    expect(later.skipped).toBe(true);
    expect(later.restB).toEqual([0]);
    expect(later.restA).toEqual([0]);
  });
});

describe("fallback accounting in diffAffected", () => {
  const entry = (name: string, versions: string[]): JsonObject => ({ package: { ecosystem: "npm", name }, versions });
  const range = (introduced: string, fixed: string): JsonObject => ({ type: "ECOSYSTEM", events: [{ introduced }, { fixed }] });
  const ranged = (name: string, ranges: JsonObject[]): JsonObject => ({ package: { ecosystem: "npm", name }, ranges });

  function run3(before: JsonObject[], after: JsonObject[], maxWork?: number): Finding[] {
    const out: Finding[] = [];
    diffAffected(before, after, out, maxWork);
    return out;
  }
  const paths = (fs: Finding[], code: string): string[] => fs.filter((f) => f.code === code).map((f) => f.path);
  const notices = (fs: Finding[]): string[] => fs.filter((f) => f.code === "pairing-limit").map((f) => f.message);

  const renamedBefore = [entry("same", ["1"]), entry("b1", ["1", "2"]), entry("b2", ["3", "4"]), entry("b3", ["5", "6"])];
  const renamedAfter = [entry("same", ["1"]), entry("a1", ["1", "2"]), entry("a2", ["3", "4"]), entry("a3", ["5", "6"])];

  it("renames every entry when the budget exactly covers the 9 comparisons of weight 3", () => {
    const out = run3(renamedBefore, renamedAfter, 27);
    expect(paths(out, "package-renamed")).toHaveLength(3);
    expect(notices(out)).toEqual([]);
  });

  it("reports every unmatched entry once when the budget is one unit short, with matching counts", () => {
    const out = run3(renamedBefore, renamedAfter, 26);
    expect(paths(out, "package-renamed")).toEqual([]);
    expect(paths(out, "package-removed")).toEqual(["affected[npm/b1]", "affected[npm/b2]", "affected[npm/b3]"]);
    expect(paths(out, "package-added")).toEqual(["affected[npm/a1]", "affected[npm/a2]", "affected[npm/a3]"]);
    expect(notices(out)).toHaveLength(1);
    expect(notices(out)[0]).toContain("the 3 removed and 3 added entries");
    expect(out.filter((f) => f.path.includes("same"))).toEqual([]);
  });

  const beforeRanges = [range("1", "1.5"), range("2", "2.5"), range("3", "3.5")];
  const afterRanges = [range("1", "1.6"), range("2", "2.6"), range("3", "3.6")];

  it("compares ranges when the budget covers the entry (weight 7) and 9 range comparisons (weight 3)", () => {
    const out = run3([ranged("p", beforeRanges)], [ranged("p", afterRanges)], 34);
    expect(paths(out, "range-event-changed")).toHaveLength(3);
    expect(notices(out)).toEqual([]);
  });

  it("reports every range once as removed and added when the budget is one unit short, with a notice", () => {
    const out = run3([ranged("p", beforeRanges)], [ranged("p", afterRanges)], 33);
    expect(paths(out, "range-event-changed")).toEqual([]);
    expect(out.filter((f) => f.code === "range-removed").map((f) => f.before)).toEqual(beforeRanges.map(canonical));
    expect(out.filter((f) => f.code === "range-added").map((f) => f.after)).toEqual(afterRanges.map(canonical));
    expect(notices(out)).toHaveLength(1);
    expect(notices(out)[0]).toMatch(/version ranges/);
  });

  it("gives a notice for each kind of fallback when entries and ranges both run out", () => {
    const before = [ranged("p", [range("1", "1.5"), range("2", "2.5")]), entry("b1", ["9"]), entry("b2", ["8"])];
    const after = [ranged("p", [range("1", "1.6"), range("2", "2.6")]), entry("a1", ["9"]), entry("a2", ["8"])];
    // Enough for the same-name entry (1 + 4 tokens) and nothing after it.
    const out = run3(before, after, 5);
    expect(paths(out, "package-removed")).toEqual(["affected[npm/b1]", "affected[npm/b2]"]);
    expect(paths(out, "package-added")).toEqual(["affected[npm/a1]", "affected[npm/a2]"]);
    expect(paths(out, "range-removed")).toHaveLength(2);
    expect(paths(out, "range-added")).toHaveLength(2);
    expect(notices(out)).toHaveLength(2);
    expect(notices(out)[0]).toContain("the 2 removed and 2 added entries");
    expect(notices(out)[1]).toMatch(/version ranges/);
  });

  it("does not announce removed and added entries when the last pair is compared as one entry", () => {
    const before = [ranged("p", [range("1", "1.5")]), entry("old", ["9"])];
    const after = [ranged("p", [range("1", "1.6")]), entry("new", ["9"])];
    // Enough for the same-name entry (1 + 2 tokens), so the rename step is skipped and step 3 pairs the rest.
    const out = run3(before, after, 3);
    expect(paths(out, "package-renamed")).toEqual(["affected[npm/new].package.name"]);
    expect(paths(out, "package-removed")).toEqual([]);
    expect(paths(out, "package-added")).toEqual([]);
    expect(notices(out).filter((m) => m.includes("removed and") && m.includes("entries"))).toEqual([]);
  });

  it("charges the size of the smaller token set when the two sides differ", () => {
    const small = ranged("p", [{ type: "ECOSYSTEM", events: [{ introduced: "1" }, { fixed: "2" }] }]);
    const large = ranged("p", [
      { type: "ECOSYSTEM", events: [{ introduced: "1" }, { fixed: "3" }, { introduced: "4" }, { fixed: "5" }] },
    ]);
    // One entry comparison and one range comparison, each 1 + 2 units.
    expect(notices(run3([small], [large], 6))).toEqual([]);
    expect(paths(run3([small], [large], 6), "range-removed")).toEqual([]);
    expect(notices(run3([small], [large], 5))).toHaveLength(1);
    expect(paths(run3([small], [large], 5), "range-removed")).toHaveLength(1);
  });

  it("gives no range notice when the ranges could never have paired", () => {
    const before = [ranged("p", [{ type: "ECOSYSTEM", events: [{ introduced: "1" }, { fixed: "2" }] }])];
    const after = [ranged("p", [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }])];
    // Enough for the entry comparison only, so the range comparison is skipped.
    const out = run3(before, after, 3);
    expect(paths(out, "range-removed")).toHaveLength(1);
    expect(paths(out, "range-added")).toHaveLength(1);
    expect(notices(out)).toEqual([]);
  });

  it("does not say the findings are below the notice, because reports list notices last", () => {
    const entries = run3(renamedBefore, renamedAfter, 26);
    const ranges = run3([ranged("p", beforeRanges)], [ranged("p", afterRanges)], 33);
    expect([...notices(entries), ...notices(ranges)].join(" ")).not.toMatch(/below/);
  });

  it("gives a range notice when only some of the skipped ranges could have paired", () => {
    const before = [ranged("p", [range("1", "1.5"), { type: "SEMVER", events: [{ introduced: "2" }, { fixed: "2.5" }] }])];
    const after = [ranged("p", [range("1", "1.6"), { type: "GIT", repo: "https://example.test/r", events: [{ introduced: "2" }, { fixed: "2.6" }] }])];
    const out = run3(before, after, 5);
    expect(paths(out, "range-removed")).toHaveLength(2);
    expect(notices(out)).toHaveLength(1);
  });

  it("reports the same findings for reversed entries past the work limit", () => {
    const b = [ranged("p", [range("1", "1.5"), range("2", "2.5")]), ranged("q", [range("3", "3.5"), range("4", "4.5"), range("5", "5.5")])];
    const a = [ranged("p", [range("1", "1.6"), range("2", "2.6")]), ranged("q", [range("3", "3.6"), range("4", "4.6"), range("5", "5.6")])];
    const totals = (fs: Finding[]): number[] =>
      ["range-event-changed", "range-removed", "range-added", "pairing-limit"].map((c) => fs.filter((f) => f.code === c).length);
    const sorted = (fs: Finding[]): string[] => fs.map((f) => `${f.code}|${f.path}|${f.message}`).sort();
    // Enough for both entry comparisons (5 + 7 units) and the 4 range comparisons of p (3 units each), not those of q.
    const forward = run3(b, a, 24);
    const backward = run3([...b].reverse(), [...a].reverse(), 24);
    expect(totals(forward)).toEqual([2, 3, 3, 1]);
    expect(sorted(backward)).toEqual(sorted(forward));
    expect(paths(forward, "range-event-changed")).toEqual(["affected[npm/p]", "affected[npm/p]"]);
  });

  it("keeps findings in array order, whatever order the budget was spent in", () => {
    const b = [ranged("z", [range("1", "1.5")]), ranged("a", [range("2", "2.5")])];
    const a = [ranged("z", [range("1", "1.6")]), ranged("a", [range("2", "2.6")])];
    expect(paths(run3(b, a), "range-event-changed")).toEqual(["affected[npm/z]", "affected[npm/a]"]);
  });

  it("gives a notice when a range list exceeds the per-list candidate limit", () => {
    const n = Math.ceil(Math.sqrt(MAX_PAIR_CANDIDATES)) + 1;
    const mk = (fixedMinor: number): JsonObject =>
      ranged("p", Array.from({ length: n }, (_, j) => range(`${j}.0.0`, `${j}.${fixedMinor}.0`)));
    const out = run3([mk(1)], [mk(2)]);
    expect(paths(out, "range-removed")).toHaveLength(n);
    expect(paths(out, "range-added")).toHaveLength(n);
    expect(notices(out)).toHaveLength(1);
    expect(notices(out)[0]).toMatch(/version ranges/);
  });
});

describe("sanitizeForTerminal coverage", () => {
  it.each([
    ["NUL", "a\u0000b", `a${BS}u0000b`],
    ["backspace", "a\u0008b", `a${BS}u0008b`],
    ["carriage return", "a\u000db", `a${BS}u000db`],
    ["delete", "a\u007fb", `a${BS}u007fb`],
    ["C1 next line", "a\u0085b", `a${BS}u0085b`],
    ["C1 control sequence introducer", "a\u009bb", `a${BS}u009bb`],
    ["combining grapheme joiner", "a\u034fb", `a${BS}u034fb`],
    ["Hangul filler", "a\u3164b", `a${BS}u3164b`],
    ["variation selector", "a\ufe0fb", `a${BS}ufe0fb`],
    ["unassigned default-ignorable", "a\u{E0FFF}b", `a${BS}u{e0fff}b`],
  ])("escapes %s", (_name, input, want) => {
    expect(sanitizeForTerminal(input)).toBe(want);
  });

  it("leaves no format, default-ignorable or separator character raw anywhere in Unicode", () => {
    const hidden = /[\p{Cf}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
    const raw: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const c = String.fromCodePoint(cp);
      if (hidden.test(c) && sanitizeForTerminal(c) === c) raw.push(cp.toString(16));
    }
    expect(raw).toEqual([]);
  });
});

describe("text report fields other than findings", () => {
  const hostile = "x\u001b[2Jy";
  const shown = `x${BS}u001b[2Jy`;
  const style = createStyle(false);

  it("escapes the advisory id and both file names in the diff report", () => {
    const bad = doc(FIXED, { id: hostile });
    const out = renderDiff(`b${hostile}.json`, `a${hostile}.json`, diff(bad, bad), style);
    expect(out.includes("\u001b")).toBe(false);
    expect(out).toContain(`  before: b${shown}.json`);
    expect(out).toContain(`  after:  a${shown}.json`);
    expect(out).toContain(`  id:     ${shown}`);
    expect(out).toContain(`Validation of a${shown}.json`);
    expect(out).toContain(`Note: b${shown}.json`);
  });

  it("escapes the file name and schema_version in the validate report", () => {
    const result = validateText(JSON.stringify(doc(FIXED, { schema_version: hostile })));
    expect(result.schemaVersion).toBe(hostile);
    const out = renderValidate(`f${hostile}.json`, result, style);
    expect(out.includes("\u001b")).toBe(false);
    expect(out).toContain(`AdvisoryGuard validate  f${shown}.json`);
    expect(out).toContain(`OSV schema_version: ${shown}`);
  });

  it("shows a default-ignorable character in a renamed package", () => {
    const after = doc(FIXED);
    (after["affected"] as any)[0].package.name = "@acme/par\u034fser";
    const r = cliDiff(doc(FIXED), after);
    expect(r.out.includes("\u034f")).toBe(false);
    expect(r.out).toContain(`@acme/par${BS}u034fser`);
  });
});

describe("JSON output of untrusted advisory values", () => {
  const nasty = "x\u009b2J\u202e\u200b\u2028\u007f\u0085\u034f\u{E0041}y";
  const unsafe = /[\u007f-\u009f\p{Cf}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
  const renamedTo = (name: string): JsonObject => {
    const after = doc(FIXED);
    (after["affected"] as any)[0].package.name = name;
    return after;
  };
  const renameFinding = (out: string): any => JSON.parse(out).findings.find((f: any) => f.code === "package-renamed");

  it("keeps unsafe characters out of the bytes, and parsing gives back the same value", () => {
    const r = cliDiff(doc(FIXED), renamedTo(nasty), ["--json"]);
    expect(unsafe.test(r.out)).toBe(false);
    expect(renameFinding(r.out).after).toBe(nasty);
  });

  it("escapes every unsafe code point and restores it exactly when parsed", () => {
    const hidden = /[\u007f-\u009f\p{Cf}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
    const raw: string[] = [];
    const wrong: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const c = String.fromCodePoint(cp);
      if (!hidden.test(c)) continue;
      const out = stringifyForTerminal({ v: c });
      if (out.includes(c)) raw.push(cp.toString(16));
      if ((JSON.parse(out) as { v: string }).v !== c) wrong.push(cp.toString(16));
    }
    expect(raw).toEqual([]);
    expect(wrong).toEqual([]);
  });

  it("keeps the same layout as plain JSON.stringify for ordinary values", () => {
    const r = cliDiff(doc(FIXED), renamedTo("caf\u00e9-\u0645"), ["--json"]);
    expect(r.out).toBe(JSON.stringify(JSON.parse(r.out), null, 2) + "\n");
  });

  it("covers the validate report too", () => {
    const file = join(tmp, "validate.json");
    writeFileSync(file, JSON.stringify(doc(FIXED, { id: nasty })));
    let out = "";
    const io: CliIo = { stdout: { write: (s: string) => ((out += s), true) }, stderr: { write: () => true }, env: {} };
    expect(run(["validate", file, "--json"], io)).toBe(2);
    expect(unsafe.test(out)).toBe(false);
    expect(JSON.parse(out).valid).toBe(false);
  });

  it("tells a literal backslash-u from the real character", () => {
    const literal = `par${BS}u200bser`;
    const real = "par\u200bser";
    expect(renameFinding(cliDiff(doc(FIXED), renamedTo(literal), ["--json"]).out).after).toBe(literal);
    expect(renameFinding(cliDiff(doc(FIXED), renamedTo(real), ["--json"]).out).after).toBe(real);
  });
});

describe("usage errors", () => {
  function cli(args: string[]): { code: number; out: string; err: string } {
    let out = "";
    let err = "";
    const io: CliIo = {
      stdout: { write: (s: string) => ((out += s), true) },
      stderr: { write: (s: string) => ((err += s), true) },
      env: {},
    };
    return { code: run(args, io), out, err };
  }

  it("escapes a file name, so it cannot control the terminal or start a new line", () => {
    const r = cli(["validate", "no-such\u001b[2J\nOK: no changes require review.json"]);
    expect(r.code).toBe(3);
    expect(r.err.includes("\u001b")).toBe(false);
    expect(r.err.split("\n").some((l) => l.startsWith("OK:"))).toBe(false);
    expect(r.err).toContain(`no-such${BS}u001b[2J${BS}u000aOK:`);
  });

  it("escapes an unknown command", () => {
    const r = cli(["cmd\u001b[2J"]);
    expect(r.code).toBe(3);
    expect(r.err.includes("\u001b")).toBe(false);
    expect(r.err).toContain(`cmd${BS}u001b[2J`);
  });

  it("keeps unsafe characters out of the JSON form, which still parses to the same message", () => {
    const r = cli(["validate", "no-such\u202e.json", "--json"]);
    expect(r.code).toBe(3);
    expect(r.out.includes("\u202e")).toBe(false);
    expect(JSON.parse(r.out).error.message).toContain("no-such\u202e.json");
  });
});

describe("keys the dedicated comparers do not read", () => {
  const score = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N";
  const url = "https://example.test/advisory";
  const other = "https://example.test/other";

  function expectBothValid(before: JsonObject, after: JsonObject): void {
    expect(validateText(JSON.stringify(before)).valid).toBe(true);
    expect(validateText(JSON.stringify(after)).valid).toBe(true);
  }

  it("reports a key removed from an event object, and names the event", () => {
    const before = doc([{ introduced: "0", note: "x" }, { fixed: "1.0.0" }]);
    const after = doc([{ introduced: "0" }, { fixed: "1.0.0" }]);
    expectBothValid(before, after);
    const r = diff(before, after);
    expect(r.status).toBe("review");
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.path).toBe("affected[npm/@acme/parser].ranges.events[introduced:0].note");
    expect(cliDiff(before, after).code).toBe(1);
  });

  it("reports a non-string value under an event kind, which the event comparer cannot read", () => {
    const before = doc([{ introduced: "0", fixed: 1 } as unknown as JsonObject, { fixed: "1.0.0" }]);
    const after = doc([{ introduced: "0" }, { fixed: "1.0.0" }]);
    expectBothValid(before, after);
    const r = diff(before, after);
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.path).toBe("affected[npm/@acme/parser].ranges.events[introduced:0].fixed");
  });

  it("reports a key removed from a top-level severity entry", () => {
    const before = doc(FIXED, { severity: [{ type: "CVSS_V3", score, note: "x" }] });
    const after = doc(FIXED, { severity: [{ type: "CVSS_V3", score }] });
    expectBothValid(before, after);
    const r = diff(before, after);
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.path).toBe("severity[CVSS_V3].note");
  });

  it("reports a key removed from an affected severity entry", () => {
    const withSeverity = (entry: JsonObject): JsonObject =>
      doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, severity: [entry], versions: ["1"] }] });
    const r = diff(withSeverity({ type: "CVSS_V3", score, note: "x" }), withSeverity({ type: "CVSS_V3", score }));
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.path).toBe("affected[npm/p].severity[CVSS_V3].note");
  });

  it("reports a key removed from a reference, and names the reference", () => {
    const before = doc(FIXED, { references: [{ type: "WEB", url: other }, { type: "WEB", url, note: "x" }] });
    const after = doc(FIXED, { references: [{ type: "WEB", url: other }, { type: "WEB", url }] });
    expectBothValid(before, after);
    const r = diff(before, after);
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.path).toBe(`references[${url}].note`);
  });

  it("adds no finding when the comparer already reports the whole item", () => {
    const refs = diff(
      doc(FIXED, { references: [{ type: "WEB", url, note: "x" }, { type: "WEB", url: other }] }),
      doc(FIXED, { references: [{ type: "WEB", url: other }] }),
    );
    expect(codes(refs)).toEqual(["reference-removed"]);
    expect(
      diff(
        doc(FIXED, { references: [{ type: "WEB", url, note: "x" }, { type: "WEB", url: other }] }),
        doc(FIXED, { references: [{ type: "WEB", url: other }] }),
        ["reference-removed"],
      ).status,
    ).toBe("clean");
    const severity = diff(doc(FIXED, { severity: [{ type: "CVSS_V3", score, note: "x" }] }), doc(FIXED, { severity: [] }));
    expect(codes(severity)).toEqual(["severity-removed"]);
    const events = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0", note: "x" }]),
      doc([{ introduced: "0" }, { fixed: "2.0.0", note: "x" }]),
    );
    expect(codes(events)).toEqual(["range-event-changed"]);
  });

  it("reports a key that moved to another item", () => {
    const r = diff(
      doc(FIXED, { references: [{ type: "WEB", url, note: "x" }, { type: "WEB", url: other }] }),
      doc(FIXED, { references: [{ type: "WEB", url }, { type: "WEB", url: other, note: "x" }] }),
    );
    expect(r.status).toBe("review");
    expect(r.findings.map((f) => [f.code, f.path])).toEqual([
      ["field-removed", `references[${url}].note`],
      ["field-added", `references[${other}].note`],
    ]);
  });

  it("treats a changed or new key like any other field, by its name", () => {
    const withKey = (key: string, value: string): JsonObject =>
      doc([{ introduced: "0", [key]: value } as JsonObject, { fixed: "1.0.0" }]);
    const changed = diff(withKey("note", "a"), withKey("note", "b"));
    expect(codes(changed)).toEqual(["field-changed"]);
    expect(changed.status).toBe("clean");
    const added = diff(doc([{ introduced: "0" }, { fixed: "1.0.0" }]), withKey("note", "a"));
    expect(codes(added)).toEqual(["field-added"]);
    expect(added.status).toBe("clean");
    expect(diff(withKey("fix_note", "a"), withKey("fix_note", "b")).status).toBe("review");
  });

  it("compares items with the same identity as an unordered list", () => {
    const r = diff(
      doc(FIXED, { references: [{ type: "WEB", url, note: "a" }, { type: "WEB", url, note: "b" }] }),
      doc(FIXED, { references: [{ type: "WEB", url, note: "b" }] }),
    );
    expect(reviewCodes(r)).toEqual(["list-item-removed"]);
    expect(r.findings[0]?.path).toBe(`references[${url}]`);
  });

  it("treats URLs that normalize to the same value as the same reference", () => {
    const r = diff(
      doc(FIXED, { references: [{ type: "WEB", url: "https://example.test/a/", note: "x" }] }),
      doc(FIXED, { references: [{ type: "WEB", url: "https://example.test/a" }] }),
    );
    expect(reviewCodes(r)).toEqual(["field-removed"]);
  });

  it("compares as a list when the number of items with one identity changes", () => {
    const r = diff(
      doc(FIXED, { references: [{ type: "WEB", url, note: "a" }] }),
      doc(FIXED, { references: [{ type: "WEB", url, note: "a" }, { type: "WEB", url, note: "b" }] }),
    );
    expect(codes(r)).toEqual(["list-item-added"]);
    expect(r.status).toBe("clean");
  });

  it("reports other keys in the same order whatever order the items are in", () => {
    const refs = (order: string[], note: boolean): JsonObject[] =>
      order.map((u) => ({ type: "WEB", url: u, ...(note ? { note: "x" } : {}) }));
    const paths = (r: { findings: Finding[] }): (string | undefined)[] => r.findings.map((f) => f.path);
    const forward = diff(doc(FIXED, { references: refs([url, other], true) }), doc(FIXED, { references: refs([url, other], false) }));
    const backward = diff(doc(FIXED, { references: refs([other, url], true) }), doc(FIXED, { references: refs([other, url], false) }));
    expect(paths(forward)).toEqual([`references[${url}].note`, `references[${other}].note`]);
    expect(paths(backward)).toEqual(paths(forward));
  });

  it("does not treat an empty URL as having no identity", () => {
    const out: Finding[] = [];
    diffReferences([{ type: "WEB", url: "", note: "x" }], [], out);
    expect(out.map((f) => f.code)).toEqual(["reference-removed"]);
  });

  it("does not lose keys on a reference with no URL, and gives them the plain path", () => {
    const out: Finding[] = [];
    diffReferences([{ type: "WEB", note: "x" }], [], out);
    expect(out.map((f) => [f.code, f.path])).toEqual([["list-item-removed", "references"]]);
  });

  it("keeps long URLs that share a beginning apart in the path", () => {
    const long = (end: string): string => `https://example.test/${"a".repeat(200)}${end}`;
    const refs = (note: boolean): JsonObject[] =>
      ["1", "2"].map((end) => ({ type: "WEB", url: long(end), ...(note ? { note: "x" } : {}) }));
    const r = diff(doc(FIXED, { references: refs(true) }), doc(FIXED, { references: refs(false) }));
    expect(new Set(r.findings.map((f) => f.path)).size).toBe(2);
  });

  it("keeps a report for a very long URL small enough to print", () => {
    const long = `https://example.test/${"a".repeat(100_000)}`;
    const keys = (note: boolean): JsonObject =>
      Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`k${i}`, note ? "x" : undefined]).filter(([, v]) => v !== undefined));
    const before = doc(FIXED, { references: [{ type: "WEB", url: long, ...keys(true) }] });
    const after = doc(FIXED, { references: [{ type: "WEB", url: long }] });
    const r = cliDiff(before, after);
    expect(r.code).toBe(1);
    expect(diff(before, after).findings.every((f) => f.path.length < 300)).toBe(true);
  });

  it("does not lose keys on an item with no identity", () => {
    const out: Finding[] = [];
    diffSeverity([{ note: "x" }], [], "severity", "", out);
    expect(out.filter((f) => f.level === "review").map((f) => f.code)).toEqual(["severity-removed", "list-item-removed"]);
  });

  it("reports nothing when those keys are unchanged, whatever the order", () => {
    const before = doc([{ introduced: "0", note: "x" }, { fixed: "1.0.0", other: "y" }]);
    const after = doc([{ fixed: "1.0.0", other: "y" }, { note: "x", introduced: "0" }]);
    expect(diff(before, after).findings).toEqual([]);
  });
});

describe("a reference entry removed while its URL stays", () => {
  const url = "https://example.test/advisory";

  it("needs review when a type is lost and nothing replaces it", () => {
    const r = diff(
      doc(FIXED, { references: [{ type: "WEB", url }, { type: "ADVISORY", url }] }),
      doc(FIXED, { references: [{ type: "WEB", url }] }),
    );
    expect(reviewCodes(r)).toEqual(["reference-removed"]);
    expect(r.findings[0]?.message).toContain("ADVISORY");
    expect(r.findings[0]?.before).toBe(url);
  });

  it("stays informational when a type is only replaced or added", () => {
    const replaced = diff(doc(FIXED, { references: [{ type: "WEB", url }] }), doc(FIXED, { references: [{ type: "ADVISORY", url }] }));
    expect(codes(replaced)).toEqual(["reference-type-changed"]);
    expect(replaced.status).toBe("clean");
    const added = diff(doc(FIXED, { references: [{ type: "WEB", url }] }), doc(FIXED, { references: [{ type: "WEB", url }, { type: "ADVISORY", url }] }));
    expect(codes(added)).toEqual(["reference-type-changed"]);
    expect(added.status).toBe("clean");
  });
});

describe("reference spelling in findings", () => {
  const spelledA = "https://Example.test/a/";
  const spelledB = "https://example.test/a";

  it("shows the first spelling of a removed or added reference", () => {
    const removed: Finding[] = [];
    diffReferences([{ type: "WEB", url: spelledA }, { type: "WEB", url: spelledB }], [], removed);
    expect(removed.map((f) => f.before)).toEqual([spelledA]);
    expect(removed[0]?.message).toContain(spelledA);
    const added: Finding[] = [];
    diffReferences([], [{ type: "WEB", url: spelledA }, { type: "WEB", url: spelledB }], added);
    expect(added.map((f) => f.after)).toEqual([spelledA]);
    expect(added[0]?.message).toContain(spelledA);
  });

  it("shows the new spelling when a reference type changes", () => {
    const out: Finding[] = [];
    diffReferences([{ type: "WEB", url: spelledB }], [{ type: "ADVISORY", url: spelledA }], out);
    expect(out.map((f) => f.code)).toEqual(["reference-type-changed"]);
    expect(out[0]?.message).toContain(spelledA);
  });
});

describe("explanations of event changes", () => {
  const whyOf = (r: { findings: Finding[] }, code: string): string => r.findings.find((f) => f.code === code)?.why ?? "";

  it("lists several same-kind ends without pairing them, because it does not compare versions", () => {
    // Sorted as text, 10.0.0 comes before 2.0.0, so pairing by position would claim 10.0.0 became 2.0.1.
    const r = diff(
      doc([{ introduced: "0" }, { fixed: "2.0.0" }, { introduced: "5.0.0" }, { fixed: "10.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "2.0.1" }, { introduced: "5.0.0" }, { fixed: "9.0.0" }]),
    );
    expect(codes(r).sort()).toEqual(["range-event-added", "range-event-added", "range-event-removed", "range-event-removed"]);
    expect(r.findings.map((f) => f.message).join(" ")).not.toContain("->");
  });

  it("still reports one replaced value in a kind as a change", () => {
    const r = diff(doc(FIXED), doc([{ introduced: "0" }, { fixed: "24.0.0" }]));
    expect(codes(r)).toEqual(["range-event-changed"]);
    expect(r.findings[0]?.message).toContain("23.0.0 -> 24.0.0");
    expect(r.findings[0]?.why).toMatch(/may change status/);
  });

  it("says open-ended only when no end remains in the range", () => {
    const fixedGone = diff(doc([{ introduced: "0" }, { fixed: "1.0.0" }]), doc([{ introduced: "0" }]));
    expect(whyOf(fixedGone, "range-event-removed")).toMatch(/open-ended/);
    const lastAffectedGone = diff(doc([{ introduced: "0" }, { last_affected: "1.0.0" }]), doc([{ introduced: "0" }]));
    expect(whyOf(lastAffectedGone, "range-event-removed")).toMatch(/open-ended/);

    const oneFixedLeft = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
      doc([{ introduced: "0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
    );
    expect(whyOf(oneFixedLeft, "range-event-removed")).not.toMatch(/open-ended/);
    expect(whyOf(oneFixedLeft, "range-event-removed")).toMatch(/Another end remains/);
    expect(whyOf(oneFixedLeft, "range-event-removed")).not.toMatch(/more versions/);
    const oneLastAffectedLeft = diff(
      doc([{ introduced: "0" }, { last_affected: "1.0.0" }, { introduced: "2.0.0" }, { last_affected: "3.0.0" }]),
      doc([{ introduced: "0" }, { introduced: "2.0.0" }, { last_affected: "3.0.0" }]),
    );
    expect(whyOf(oneLastAffectedLeft, "range-event-removed")).not.toMatch(/open-ended/);
    expect(whyOf(oneLastAffectedLeft, "range-event-removed")).toMatch(/Another end remains/);
  });

  it("keeps the explanation of an introduced event when an end remains", () => {
    const r = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { fixed: "3.0.0" }]),
    );
    expect(whyOf(r, "range-event-removed")).toMatch(/where the vulnerable range starts/);
  });

  it("does not pair one value with several, in either direction", () => {
    const fewer = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "9.0.0" }, { introduced: "2.0.0" }]),
    );
    expect(codes(fewer)).not.toContain("range-event-changed");
    const more = diff(
      doc([{ introduced: "0" }, { fixed: "9.0.0" }, { introduced: "2.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }]),
    );
    expect(codes(more)).not.toContain("range-event-changed");
  });

  it("does not say new start events mark more versions when they may narrow the range", () => {
    const r = diff(
      doc([{ introduced: "1.0.0" }, { fixed: "2.0.0" }, { introduced: "5.0.0" }, { fixed: "6.0.0" }]),
      doc([{ introduced: "1.5.0" }, { fixed: "2.0.0" }, { introduced: "5.5.0" }, { fixed: "6.0.0" }]),
    );
    expect(whyOf(r, "range-event-added")).not.toMatch(/marks additional/);
    expect(whyOf(r, "range-event-added")).toMatch(/may be marked as vulnerable/);
  });

  it("does not state as certain what a new end or a limit does to the range", () => {
    const lastAffected = diff(doc([{ introduced: "0" }]), doc([{ introduced: "0" }, { last_affected: "1.0.0" }]));
    expect(whyOf(lastAffected, "range-event-added")).toMatch(/may be treated as unaffected unless another interval covers them/);
    const git = (events: JsonObject[]): JsonObject =>
      doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, ranges: [{ type: "GIT", repo: "https://example.test/r", events }] }] });
    const hash = "a".repeat(40);
    const added = diff(git([{ introduced: "0" }]), git([{ introduced: "0" }, { limit: hash }]));
    expect(whyOf(added, "range-event-added")).toMatch(/may narrow/);
    const removed = diff(git([{ introduced: "0" }, { limit: hash }]), git([{ introduced: "0" }]));
    expect(whyOf(removed, "range-event-removed")).toMatch(/may widen/);
  });

  it("does not say a new fixed event ends the range earlier when it closes a new interval", () => {
    const r = diff(
      doc(FIXED),
      doc([{ introduced: "0" }, { fixed: "23.0.0" }, { introduced: "25.0.0" }, { fixed: "26.0.0" }]),
    );
    expect(whyOf(r, "range-event-added")).not.toMatch(/earlier/);
    expect(r.findings.map((f) => f.why ?? "").join(" ")).toMatch(/unless another interval covers them/);
  });
});

describe("conversion wording in cases the tool can tell apart", () => {
  const only = (r: { findings: Finding[] }): Finding => {
    const found = r.findings.filter((f) => f.code === "range-bound-converted");
    expect(found).toHaveLength(1);
    return found[0] as Finding;
  };

  it("does not say the range ends when an interval in it stays open", () => {
    const f = only(
      diff(
        doc([{ introduced: "0" }, { last_affected: "1.0.0" }, { introduced: "2.0.0" }]),
        doc([{ introduced: "0" }, { fixed: "1.0.1" }, { introduced: "2.0.0" }]),
      ),
    );
    expect(f.message).not.toMatch(/range now ends|ends below/);
    expect(f.message).toContain("an inclusive end at 1.0.0 became an exclusive end at 1.0.1");
  });

  it("talks about commits and the repository for a GIT range", () => {
    const hash = (c: string): string => c.repeat(40);
    const git = (events: JsonObject[]): JsonObject =>
      doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, ranges: [{ type: "GIT", repo: "https://example.test/r", events }] }] });
    const f = only(
      diff(git([{ introduced: "0" }, { last_affected: hash("a") }]), git([{ introduced: "0" }, { fixed: hash("b") }])),
    );
    expect(f.why).toMatch(/that commit is affected/);
    expect(f.why).toMatch(/which commits are affected/);
    expect(f.why).toMatch(/repository/);
    expect(f.why).not.toMatch(/release|package/);
    expect(f.message).toContain(`an inclusive end at ${hash("a")} became an exclusive end at ${hash("b")}`);
  });

  it("states the flip at that end when the value stays the same, in both directions", () => {
    const toFixed = only(
      diff(doc([{ introduced: "0" }, { last_affected: "1.0.0" }]), doc([{ introduced: "0" }, { fixed: "1.0.0" }])),
    );
    expect(toFixed.message).toContain("this end no longer includes 1.0.0");
    expect(toFixed.why).not.toMatch(/may change nothing/);
    expect(toFixed.why).toMatch(/Confirm which is correct/);
    expect(toFixed.why).toMatch(/may still cover it/);

    const toLastAffected = only(
      diff(doc([{ introduced: "0" }, { fixed: "1.0.0" }]), doc([{ introduced: "0" }, { last_affected: "1.0.0" }])),
    );
    expect(toLastAffected.message).toContain("this end now includes 1.0.0");
    expect(toLastAffected.message).toMatch(/no longer names a patched version/);
    expect(toLastAffected.why).not.toMatch(/may change nothing/);
  });

  it("does not say may change nothing when one of several values stays, and still does not pair them", () => {
    const f = only(
      diff(
        doc([{ introduced: "0" }, { last_affected: "1.0.0" }, { introduced: "5.0.0" }, { last_affected: "6.0.0" }]),
        doc([{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "5.0.0" }, { fixed: "7.0.0" }]),
      ),
    );
    expect(f.why).not.toMatch(/may change nothing/);
    expect(f.why).toMatch(/Confirm which is correct/);
    expect(f.message).toMatch(/not paired/);
    expect(f.message).not.toMatch(/same value/);
  });

  it("talks about commits in every GIT form", () => {
    const hash = (c: string): string => c.repeat(40);
    const git = (events: JsonObject[]): JsonObject =>
      doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, ranges: [{ type: "GIT", repo: "https://example.test/r", events }] }] });
    const same = only(diff(git([{ introduced: "0" }, { last_affected: hash("a") }]), git([{ introduced: "0" }, { fixed: hash("a") }])));
    expect(same.why).toMatch(/that commit is affected/);
    expect(same.why).not.toMatch(/version/);
    const reverse = only(diff(git([{ introduced: "0" }, { fixed: hash("a") }]), git([{ introduced: "0" }, { last_affected: hash("b") }])));
    expect(reverse.message).toMatch(/no longer names a patched commit/);
    const several = only(
      diff(
        git([{ introduced: "0" }, { last_affected: hash("a") }, { introduced: hash("c") }, { last_affected: hash("d") }]),
        git([{ introduced: "0" }, { fixed: hash("b") }, { introduced: hash("c") }, { fixed: hash("e") }]),
      ),
    );
    expect(several.message).toMatch(/does not compare commits/);
    expect(several.message).not.toMatch(/version/);
  });

  it("lists several values in the reverse direction, and says when no patched version remains", () => {
    const f = only(
      diff(
        doc([{ introduced: "0" }, { fixed: "2.0.1" }, { introduced: "5.0.0" }, { fixed: "9.0.0" }]),
        doc([{ introduced: "0" }, { last_affected: "2.0.0" }, { introduced: "5.0.0" }, { last_affected: "10.0.0" }]),
      ),
    );
    expect(f.before).toEqual(["2.0.1", "9.0.0"]);
    expect(f.after).toEqual(["10.0.0", "2.0.0"]);
    expect(f.message).toMatch(/not paired/);
    expect(f.message).toMatch(/Also, this range no longer names a patched version/);
  });

  it("does not call an edit a conversion when the target kind also lost a value", () => {
    // Mixing both kinds in one range is invalid OSV, but the comparison still has to describe it correctly.
    const r = diff(
      doc([{ introduced: "0" }, { fixed: "1.0.0" }, { last_affected: "2.0.0" }]),
      doc([{ introduced: "0" }, { fixed: "3.0.0" }]),
    );
    expect(codes(r).sort()).toEqual(["range-event-changed", "range-event-removed"]);
  });

  it("gives the same message and values whatever order the events are in", () => {
    const before = doc([{ introduced: "0" }, { last_affected: "2.0.0" }, { introduced: "5.0.0" }, { last_affected: "6.0.0" }]);
    const a = only(diff(before, doc([{ introduced: "0" }, { fixed: "2.0.1" }, { introduced: "5.0.0" }, { fixed: "7.0.0" }])));
    const b = only(diff(before, doc([{ fixed: "7.0.0" }, { introduced: "5.0.0" }, { fixed: "2.0.1" }, { introduced: "0" }])));
    expect(b.message).toBe(a.message);
    expect(b.after).toEqual(a.after);
  });
});

describe("invalid input is reported as invalid, not as an internal error", () => {
  const hostileType = { toString: 1, valueOf: 1 };

  it("handles an object as a range type or repo, whether or not the ranges pair", () => {
    const withHostile = (events: JsonObject[]): JsonObject => {
      const d = doc(events);
      const range = (d["affected"] as any)[0].ranges[0];
      range.type = hostileType;
      range.repo = hostileType;
      return d;
    };
    // Removed and added ranges.
    expect(cliDiff(doc(FIXED), withHostile(FIXED)).code).toBe(2);
    // The edited file is valid here, so the ranges are simply reported as removed and added.
    expect(cliDiff(withHostile(FIXED), doc(FIXED)).code).toBe(1);
    // Paired ranges with a changed event.
    const paired = cliDiff(withHostile(FIXED), withHostile([{ introduced: "0" }, { fixed: "24.0.0" }]));
    expect(paired.code).toBe(2);
    expect(paired.out).toContain("23.0.0 -> 24.0.0");
  });

  it("does not make scoring slower for invalid range types", () => {
    const big = { ...Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`k${i}`, i])) };
    const ranges = (fixed: string): JsonObject[] =>
      Array.from({ length: 200 }, (_, i) => ({ type: big, events: [{ introduced: `${i}` }, { fixed }] })) as unknown as JsonObject[];
    const t0 = Date.now();
    const out: Finding[] = [];
    diffAffected(
      [{ package: { ecosystem: "npm", name: "p" }, ranges: ranges("1") }],
      [{ package: { ecosystem: "npm", name: "p" }, ranges: ranges("2") }],
      out,
    );
    expect(Date.now() - t0).toBeLessThan(10000);
    expect(out.filter((f) => f.code === "range-event-changed")).toHaveLength(200);
  });

  it("uses the usual wording when a range type is null", () => {
    const withNull = (fixed: string): JsonObject[] => [
      { package: { ecosystem: "npm", name: "p" }, ranges: [{ type: null, events: [{ introduced: "0" }, { fixed }] }] },
    ] as unknown as JsonObject[];
    const out: Finding[] = [];
    diffAffected(withNull("1"), withNull("2"), out);
    expect(out[0]?.message).toContain("in range range of npm/p");
  });

  it("handles a very large number of schema errors", () => {
    const text = JSON.stringify(doc(FIXED, { references: Array.from({ length: 200_000 }, () => 1) }));
    const result = validateText(text);
    expect(result.valid).toBe(false);
    expect(result.findings.length).toBeGreaterThan(100_000);
  });
});

describe("limits outside affected", () => {
  const over = Math.ceil(Math.sqrt(MAX_PAIR_CANDIDATES)) + 1;

  it("gives a notice when a custom list exceeds the per-list limit", () => {
    const mk = (note: string): JsonObject =>
      doc(FIXED, { database_specific: { list: Array.from({ length: over }, (_, id) => ({ id, note })) } });
    const r = diff(mk("a"), mk("b"));
    expect(codes(r).filter((c) => c === "list-item-removed")).toHaveLength(over);
    expect(codes(r).filter((c) => c === "list-item-added")).toHaveLength(over);
    const notices = r.findings.filter((f) => f.code === "pairing-limit");
    expect(notices.map((f) => f.path)).toEqual(["database_specific.list"]);
    expect(notices[0]?.level).toBe("review");
    expect(notices[0]?.message).toMatch(/may be reported as removed and added/);
  });

  it("does not give one when the list items could never have been paired", () => {
    const mk = (tag: string): JsonObject =>
      doc(FIXED, { database_specific: { list: Array.from({ length: over }, (_, i) => `${tag}-${i}`) } });
    const strings = diff(mk("a"), mk("b"));
    expect(codes(strings)).not.toContain("pairing-limit");
    expect(diff(mk("a"), mk("b"), ["list-item-removed"]).status).toBe("clean");

    const severity = (tag: string): JsonObject[] => Array.from({ length: over }, (_, i) => ({ type: `${tag}${i}`, score: "x" }));
    const out: Finding[] = [];
    diffSeverity(severity("a"), severity("b"), "severity", "", out);
    expect(out.map((f) => f.code)).not.toContain("pairing-limit");
  });

  it("does not give one below the limit", () => {
    const mk = (note: string): JsonObject =>
      doc(FIXED, { database_specific: { list: [0, 1, 2].map((id) => ({ id, note })) } });
    expect(codes(diff(mk("a"), mk("b")))).toEqual(["field-changed", "field-changed", "field-changed"]);
  });

  it("gives a notice when a severity list exceeds the per-list limit", () => {
    const mk = (tag: string): JsonObject[] =>
      Array.from({ length: over }, (_, i) => ({ type: "CVSS_V3", score: `${tag}-${i}` }));
    const out: Finding[] = [];
    diffSeverity(mk("a"), mk("b"), "severity", "", out);
    expect(out.filter((f) => f.code === "pairing-limit").map((f) => [f.path, f.level])).toEqual([["severity", "review"]]);
    expect(out.filter((f) => f.code === "severity-removed")).toHaveLength(over);
  });
});

describe("a matching limit in the verdict", () => {
  const over = Math.ceil(Math.sqrt(MAX_PAIR_CANDIDATES)) + 1;
  const entries = (prefix: string): JsonObject =>
    doc(FIXED, {
      affected: Array.from({ length: over }, (_, i) => ({
        package: { ecosystem: "npm", name: `${prefix}${i}` },
        versions: [`${i}.0.0`],
      })),
    });
  const ranges = (minor: number): JsonObject =>
    doc(FIXED, {
      affected: [
        {
          package: { ecosystem: "npm", name: "p" },
          ranges: Array.from({ length: over }, (_, j) => ({ type: "ECOSYSTEM", events: [{ introduced: `${j}.0.0` }, { fixed: `${j}.${minor}.0` }] })),
        },
      ],
    });

  it("stays in review when the removed and added codes are allowed for entries", () => {
    const allow = ["package-removed", "package-added"];
    expect(diff(entries("b"), entries("a"), allow).status).toBe("review");
    expect(cliDiff(entries("b"), entries("a"), ["--allow", allow.join(",")]).code).toBe(1);
  });

  it("stays in review when the removed and added codes are allowed for ranges", () => {
    const allow = ["range-removed", "range-added"];
    expect(diff(ranges(1), ranges(2), allow).status).toBe("review");
  });

  it("passes only when the limit itself is allowed too", () => {
    expect(diff(entries("b"), entries("a"), ["package-removed", "package-added", "pairing-limit"]).status).toBe("clean");
    expect(diff(ranges(1), ranges(2), ["range-removed", "range-added", "pairing-limit"]).status).toBe("clean");
  });

  it("explains why the limit needs review", () => {
    const notice = diff(ranges(1), ranges(2)).findings.find((f) => f.code === "pairing-limit");
    expect(notice?.level).toBe("review");
    expect(notice?.why).toMatch(/not fully compared/);
  });

  it("does not need review below the limit", () => {
    expect(codes(diff(doc(FIXED), doc(FIXED)))).toEqual([]);
  });
});

describe("array order does not decide a result", () => {
  const sortedFindings = (r: { findings: Finding[] }): string[] => r.findings.map((f) => `${f.code}|${f.path}|${f.message}`).sort();
  function permutations<T>(items: T[]): T[][] {
    if (items.length < 2) return [items];
    return items.flatMap((item, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]));
  }
  function expectSameAcrossOrders<T>(before: T[], after: T[], build: (list: T[]) => JsonObject, allowCodes: string[]): void {
    const first = diff(build(before), build(after));
    for (const b of permutations(before)) {
      for (const a of permutations(after)) {
        expect(sortedFindings(diff(build(b), build(a)))).toEqual(sortedFindings(first));
        for (const code of allowCodes) {
          expect(diff(build(b), build(a), [code]).status).toBe(diff(build(before), build(after), [code]).status);
        }
      }
    }
  }

  it("pairs tied ranges the same way, including when one pairing would be a conversion", () => {
    const withRanges = (rs: JsonObject[]): JsonObject => doc(FIXED, { affected: [{ package: { ecosystem: "npm", name: "p" }, ranges: rs }] });
    const range = (events: JsonObject[]): JsonObject => ({ type: "ECOSYSTEM", events });
    const before = [range([{ introduced: "1" }, { fixed: "2" }]), range([{ introduced: "3" }, { last_affected: "4" }])];
    const after = [range([{ introduced: "5" }, { fixed: "6" }]), range([{ introduced: "7" }, { last_affected: "8" }])];
    expectSameAcrossOrders(before, after, withRanges, ["range-event-changed", "range-bound-converted"]);
  });

  it("pairs tied renamed entries the same way", () => {
    const withEntries = (es: JsonObject[]): JsonObject => doc(FIXED, { affected: es });
    const entry = (name: string, versions: string[]): JsonObject => ({ package: { ecosystem: "npm", name }, versions });
    const before = [entry("a", ["1", "2"]), entry("b", ["1", "3"])];
    const after = [entry("c", ["1", "4"]), entry("d", ["1", "5"])];
    expectSameAcrossOrders(before, after, withEntries, ["package-renamed", "versions-removed"]);
  });

  it("pairs tied severity entries of one type the same way", () => {
    const score = (c: string): string => `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:${c}/I:N/A:N`;
    const severity = (c: string, extra = "N"): JsonObject => ({ type: "CVSS_V3", score: `${score(c).slice(0, -3)}A:${extra}` });
    const withSeverity = (ss: JsonObject[]): JsonObject => doc(FIXED, { severity: ss });
    expectSameAcrossOrders([severity("L"), severity("H")], [severity("N", "L"), severity("N", "H")], withSeverity, ["severity-changed"]);
  });

  it("gives the same codes and values for tied items in a custom list", () => {
    const withList = (list: JsonObject[]): JsonObject => doc(FIXED, { database_specific: { list } });
    const item = (x: string): JsonObject => ({ id: 1, x });
    const pairsOf = (r: { findings: Finding[] }): string[] => r.findings.map((f) => `${f.code}|${String(f.before)}|${String(f.after)}`).sort();
    const first = pairsOf(diff(withList([item("a"), item("b")]), withList([item("c"), item("d")])));
    for (const b of permutations([item("a"), item("b")])) {
      for (const a of permutations([item("c"), item("d")])) {
        expect(pairsOf(diff(withList(b), withList(a)))).toEqual(first);
      }
    }
  });
});

describe("pairing constants and boundaries", () => {
  it("matches the limits the README documents", () => {
    expect(MAX_MATCHING_WORK).toBe(20_000_000);
    expect(MAX_PAIR_CANDIDATES).toBe(250_000);
  });

  it("allows exactly the candidate limit and skips one above it", () => {
    const pair = (maxCandidates: number) =>
      pairItems(["b0", "b1"], ["a0", "a1"], (s) => s, (s) => s, () => 1, { maxCandidates });
    expect(pair(4).skipped).toBe(false);
    expect(pair(3).skipped).toBe(true);
  });

  it("looks up the smaller set's members in the larger set", () => {
    class CountingSet extends Set<string> {
      lookups = 0;
      override has(value: string): boolean {
        this.lookups++;
        return super.has(value);
      }
    }
    const small = new CountingSet(["1", "2"]);
    const large = new CountingSet(["1", "2", "3", "4", "5"]);
    expect(overlap(small, large)).toBe(2);
    expect(large.lookups).toBe(2);
    expect(small.lookups).toBe(0);
    large.lookups = 0;
    expect(overlap(large, small)).toBe(2);
    expect(large.lookups).toBe(2);
    expect(small.lookups).toBe(0);
  });
});

// Coarse checks at full scale. The elapsed-time limits only catch a large regression and do not
// promise a run time; the exact accounting is checked by the deterministic tests above.
describe("matching work stays bounded at full scale", () => {
  it("pairs a very long run of identical items in the exact phase without quadratic work", () => {
    const items = Array.from({ length: 200_000 }, () => "same");
    const t0 = Date.now();
    const r = pairItems(items, items, (s) => s, (s) => s, () => -1);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.pairs).toHaveLength(200_000);
    expect(r.restB).toEqual([]);
  });

  it("gives up on renames when unmatched entries carry too many versions, and still reports every entry", () => {
    const versions = Array.from({ length: 1000 }, (_, i) => `${i}`);
    const mk = (prefix: string): JsonObject =>
      doc(FIXED, {
        affected: Array.from({ length: 500 }, (_, i) => ({ package: { ecosystem: "npm", name: `${prefix}${i}` }, versions })),
      });
    const before = mk("b");
    const after = mk("a");
    const t0 = Date.now();
    const r = diff(before, after);
    expect(Date.now() - t0).toBeLessThan(30000);
    expect(codes(r)).toContain("pairing-limit");
    expect(codes(r).filter((c) => c === "package-removed")).toHaveLength(500);
    expect(codes(r).filter((c) => c === "package-added")).toHaveLength(500);
    expect(r.status).toBe("review");
  });

  it("limits range matching across the whole document, and still reports every entry", () => {
    const mk = (fixedMinor: number): JsonObject =>
      doc(FIXED, {
        affected: Array.from({ length: 300 }, (_, i) => ({
          package: { ecosystem: "npm", name: `p${i}` },
          ranges: Array.from({ length: 300 }, (_, j) => ({
            type: "ECOSYSTEM",
            events: [{ introduced: `${j}.0.0` }, { fixed: `${j}.${fixedMinor}.0` }],
          })),
        })),
      });
    const before = mk(1);
    const after = mk(2);
    const t0 = Date.now();
    const r = diff(before, after);
    expect(Date.now() - t0).toBeLessThan(30000);
    expect(codes(r)).toContain("pairing-limit");
    expect(new Set(r.findings.filter((f) => f.level === "review" && f.code !== "pairing-limit").map((f) => f.path)).size).toBe(300);
    expect(r.status).toBe("review");
  });

  it("handles a long list of removed references without quadratic work", () => {
    const refs = Array.from({ length: 100_000 }, (_, i) => ({ type: "WEB", url: `https://example.test/${i}` }));
    const before = doc(FIXED, { references: refs });
    const out: Finding[] = [];
    const t0 = Date.now();
    diffReferences(before["references"], [], out);
    expect(Date.now() - t0).toBeLessThan(20000);
    expect(out).toHaveLength(100_000);
    expect(out[0]?.before).toBe("https://example.test/0");
  });

  it("still detects renames when the matching work is small", () => {
    const mk = (a: string, b: string): JsonObject =>
      doc(FIXED, {
        affected: [
          { package: { ecosystem: "npm", name: a }, versions: ["1.0.0", "1.0.1"] },
          { package: { ecosystem: "npm", name: b }, versions: ["2.0.0", "2.0.1"] },
        ],
      });
    const r = diff(mk("aa", "bb"), mk("aa2", "bb2"));
    expect(codes(r).filter((c) => c === "package-renamed")).toHaveLength(2);
    expect(codes(r)).not.toContain("pairing-limit");
  });
});
