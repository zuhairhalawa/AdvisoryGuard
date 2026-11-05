// Checks for three edit shapes seen in real advisory pull requests. The records are synthetic.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { run } from "../src/cli/main.js";
import type { CliIo } from "../src/cli/main.js";
import type { JsonObject } from "../src/core/types.js";
import { validateText } from "../src/index.js";
import { renderDiff } from "../src/report/text.js";
import { createStyle } from "../src/report/style.js";
import { codes, diff, reviewCodes } from "./helpers.js";

const tmp = mkdtempSync(join(tmpdir(), "advisoryguard-real-edits-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const KNOWN = "last_known_affected_version_range";

interface EntryOptions {
  known?: unknown;
  ecosystem?: string;
  type?: string;
  extra?: Record<string, unknown>;
}

function entry(name: string, events: JsonObject[], opts: EntryOptions = {}): JsonObject {
  const { known, ecosystem = "Maven", type = "ECOSYSTEM", extra = {} } = opts;
  return {
    package: { ecosystem, name },
    ranges: [{ type, events }],
    ...(known === undefined ? {} : { database_specific: { [KNOWN]: known } }),
    ...extra,
  } as JsonObject;
}

function record(...affected: JsonObject[]): JsonObject {
  return {
    schema_version: "1.4.0",
    id: "GHSA-2222-3333-4444",
    modified: "2026-01-01T00:00:00Z",
    published: "2026-01-01T00:00:00Z",
    summary: "Synthetic advisory",
    details: "Synthetic advisory used for local regression tests.",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" }],
    affected,
    references: [{ type: "WEB", url: "https://example.test/advisory" }],
  } as JsonObject;
}

function cli(args: string[]): { code: number; out: string } {
  let out = "";
  const io: CliIo = { stdout: { write: (s: string) => ((out += s), true) }, stderr: { write: () => true }, env: {} };
  return { code: run(args, io), out };
}

function cliDiff(before: JsonObject, after: JsonObject, extra: string[] = []): { code: number; out: string } {
  const b = join(tmp, "before.json");
  const a = join(tmp, "after.json");
  writeFileSync(b, JSON.stringify(before));
  writeFileSync(a, JSON.stringify(after));
  return cli(["diff", b, a, ...extra]);
}

const OPEN: JsonObject[] = [{ introduced: "0" }];
const fixedAt = (v: string): JsonObject[] => [{ introduced: "0" }, { fixed: v }];
const lastAt = (v: string): JsonObject[] => [{ introduced: "0" }, { last_affected: v }];

describe("a known range replaced by an end event", () => {
  const before = record(entry("a:lib", OPEN, { known: "< 2.1.0" }));
  const after = record(entry("a:lib", fixedAt("2.1.0")));

  it("is one review finding, not an added event and a removed field", () => {
    const r = diff(before, after);
    expect(reviewCodes(r)).toEqual(["known-range-converted"]);
    expect(codes(r)).not.toContain("field-removed");
    expect(codes(r)).not.toContain("range-event-added");
    const f = r.findings[0];
    expect(f?.before).toBe("< 2.1.0");
    expect(f?.after).toBe("2.1.0");
    expect(f?.message).toContain("< 2.1.0");
    expect(f?.message).toContain("same");
    expect(f?.why).toMatch(/flagged/);
  });

  it("treats <= and last_affected as the same end", () => {
    const r = diff(record(entry("a:lib", OPEN, { known: "<= 2.0.9" })), record(entry("a:lib", lastAt("2.0.9"))));
    expect(reviewCodes(r)).toEqual(["known-range-converted"]);
    expect(r.findings[0]?.message).toContain("same");
  });

  it.each([
    ["a different value", "< 2.1.0", fixedAt("3.0.0")],
    ["<= with fixed at that value", "<= 2.1.0", fixedAt("2.1.0")],
    ["< with last_affected at that value", "< 2.1.0", lastAt("2.1.0")],
    ["a form it cannot read", ">= 1.0, < 2.1.0", fixedAt("2.1.0")],
  ])("says so when the two do not name the same end: %s", (_name, known, events) => {
    const r = diff(record(entry("a:lib", OPEN, { known })), record(entry("a:lib", events)));
    expect(reviewCodes(r)).toEqual(["known-range-converted"]);
    const f = r.findings[0];
    expect(f?.message).not.toContain("both name");
    expect(f?.message).toContain("do not name");
    expect(f?.why).toContain("does not compare versions");
  });

  it("needs its own code in an allow list", () => {
    expect(diff(before, after, ["known-range-converted"]).status).toBe("clean");
    expect(diff(before, after, ["range-event-added", "field-removed"]).status).toBe("review");
    expect(cliDiff(before, after).code).toBe(1);
    expect(cliDiff(before, after, ["--allow", "known-range-converted"]).code).toBe(0);
  });

  it("still reports another key dropped from database_specific", () => {
    const b = record(entry("a:lib", OPEN, { extra: { database_specific: { [KNOWN]: "< 2.1.0", note: "kept" } } }));
    const r = diff(b, record(entry("a:lib", fixedAt("2.1.0"))));
    expect(reviewCodes(r).sort()).toEqual(["field-removed", "known-range-converted"]);
    const removed = r.findings.find((f) => f.code === "field-removed");
    expect(removed?.before).toEqual({ note: "kept" });
    expect(removed?.message).not.toContain(KNOWN);
  });

  it("does not report database_specific when only the known range left it", () => {
    const b = record(entry("a:lib", OPEN, { extra: { database_specific: { [KNOWN]: "< 2.1.0", note: "kept" } } }));
    const a = record(entry("a:lib", fixedAt("2.1.0"), { extra: { database_specific: { note: "kept" } } }));
    expect(reviewCodes(diff(b, a))).toEqual(["known-range-converted"]);
    const emptied = record(entry("a:lib", fixedAt("2.1.0"), { extra: { database_specific: {} } }));
    expect(reviewCodes(diff(before, emptied))).toEqual(["known-range-converted"]);
  });

  it("does not apply when no end was added", () => {
    const r = diff(before, record(entry("a:lib", OPEN)));
    expect(reviewCodes(r)).toEqual(["field-removed"]);
  });

  it("does not apply when the known range stays", () => {
    const r = diff(before, record(entry("a:lib", fixedAt("2.1.0"), { known: "< 2.1.0" })));
    expect(reviewCodes(r)).toEqual(["range-event-added"]);
  });

  it("does not apply when an end was also removed", () => {
    const r = diff(record(entry("a:lib", lastAt("2.0.0"), { known: "<= 2.0.0" })), record(entry("a:lib", fixedAt("2.1.0"))));
    expect(reviewCodes(r).sort()).toEqual(["known-range-removed", "range-bound-converted"]);
  });

  it("does not apply when the known range is not a string", () => {
    const r = diff(record(entry("a:lib", OPEN, { known: 5 })), record(entry("a:lib", fixedAt("2.1.0"))));
    expect(reviewCodes(r).sort()).toEqual(["field-removed", "range-event-added"]);
  });

  it("does not guess between two ranges that each gain an end, in either order", () => {
    const rangeA = { type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }] };
    const rangeB = { type: "ECOSYSTEM", events: [{ introduced: "5.0.0" }] };
    const endA = { type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] };
    const endB = { type: "ECOSYSTEM", events: [{ introduced: "5.0.0" }, { fixed: "6.0.0" }] };
    const mk = (ranges: unknown[], known?: string): JsonObject =>
      record({ package: { ecosystem: "Maven", name: "a:lib" }, ranges, ...(known ? { database_specific: { [KNOWN]: known } } : {}) } as JsonObject);
    const r1 = diff(mk([rangeA, rangeB], "< 6.0.0"), mk([endA, endB]));
    const r2 = diff(mk([rangeB, rangeA], "< 6.0.0"), mk([endB, endA]));
    expect(reviewCodes(r1).sort()).toEqual(["known-range-removed", "range-event-added", "range-event-added"]);
    expect(reviewCodes(r2).sort()).toEqual(reviewCodes(r1).sort());
  });
});

describe("a known range removed while the range keeps an end", () => {
  const before = record(entry("a:lib", fixedAt("8.6.1"), { known: "<= 8.6.0" }));
  const after = record(entry("a:lib", fixedAt("8.6.1")));

  it("is its own review finding, without the dropped by accident wording", () => {
    const r = diff(before, after);
    expect(reviewCodes(r)).toEqual(["known-range-removed"]);
    expect(codes(r)).not.toContain("field-removed");
    const f = r.findings[0];
    expect(f?.before).toBe("<= 8.6.0");
    expect(f?.message).toContain("<= 8.6.0");
    expect(f?.message).toContain("fixed");
    expect(f?.message).toContain("8.6.1");
    expect(f?.why).not.toContain("accident");
    expect(f?.why).toContain("same end");
  });

  it("does not loosen the exit code", () => {
    expect(diff(before, after).status).toBe("review");
    expect(cliDiff(before, after).code).toBe(1);
  });

  it("says so when the end also moved", () => {
    const r = diff(record(entry("a:lib", fixedAt("8.0.32"), { known: "<= 8.0.31" })), record(entry("a:lib", fixedAt("8.0.33"))));
    expect(reviewCodes(r).sort()).toEqual(["known-range-removed", "range-event-changed"]);
    const f = r.findings.find((x) => x.code === "known-range-removed");
    expect(f?.why).toContain("also changed");
    expect(f?.why).not.toContain("same end");
  });

  it("does not call a reordered range a moved end", () => {
    const events: JsonObject[] = [{ introduced: "0" }, { fixed: "1" }, { introduced: "2" }, { last_affected: "3" }];
    const r = diff(record(entry("a:lib", events, { known: "<= 3" })), record(entry("a:lib", [...events].reverse())));
    expect(r.findings.find((x) => x.code === "known-range-removed")?.why).toContain("same end");
  });

  it("works with last_affected as the end", () => {
    const r = diff(record(entry("a:lib", lastAt("2"), { known: "< 3" })), record(entry("a:lib", lastAt("2"))));
    expect(reviewCodes(r)).toEqual(["known-range-removed"]);
    expect(r.findings[0]?.message).toContain("last_affected");
  });

  it("stays a dropped field when no end remains, because that really can lose data", () => {
    const r = diff(record(entry("a:lib", OPEN, { known: "< 2" })), record(entry("a:lib", OPEN)));
    expect(reviewCodes(r)).toEqual(["field-removed"]);
    expect(r.findings[0]?.why).toContain("accident");
  });

  it("does not replace the conversion finding when the note became the end", () => {
    const r = diff(record(entry("a:lib", OPEN, { known: "< 2" })), record(entry("a:lib", fixedAt("2"))));
    expect(reviewCodes(r)).toEqual(["known-range-converted"]);
  });

  it("stays quiet when the note stays", () => {
    const r = diff(before, record(entry("a:lib", fixedAt("8.6.1"), { known: "<= 8.6.0" })));
    expect(codes(r)).toEqual([]);
  });

  it("treats a note that is not a string as an ordinary dropped field", () => {
    const r = diff(record(entry("a:lib", fixedAt("2"), { known: 5 })), record(entry("a:lib", fixedAt("2"))));
    expect(reviewCodes(r)).toEqual(["field-removed"]);
  });

  it("needs its own code in an allow list, which does not hide other removed fields", () => {
    expect(diff(before, after, ["known-range-removed"]).status).toBe("clean");
    expect(diff(before, after, ["field-removed"]).status).toBe("review");
    expect(cliDiff(before, after, ["--allow", "known-range-removed"]).code).toBe(0);
    const b = record(entry("a:lib", fixedAt("2"), { extra: { database_specific: { [KNOWN]: "< 2", note: "kept" } } }));
    expect(diff(b, record(entry("a:lib", fixedAt("2"))), ["known-range-removed"]).status).toBe("review");
  });

  it("still reports another key dropped from database_specific", () => {
    const b = record(entry("a:lib", fixedAt("2"), { extra: { database_specific: { [KNOWN]: "<= 1", note: "kept" } } }));
    const r = diff(b, record(entry("a:lib", fixedAt("2"))));
    expect(reviewCodes(r).sort()).toEqual(["field-removed", "known-range-removed"]);
    const removed = r.findings.find((f) => f.code === "field-removed");
    expect(removed?.before).toEqual({ note: "kept" });
  });
});

describe("packages left out of a version change", () => {
  it("names the package that kept the old range", () => {
    const r = diff(
      record(entry("a:api", OPEN, { known: "< 2.1.0" }), entry("a:server", OPEN, { known: "< 2.1.0" })),
      record(entry("a:api", fixedAt("2.1.0")), entry("a:server", OPEN, { known: "< 2.1.0" })),
    );
    expect(reviewCodes(r).sort()).toEqual(["known-range-converted", "sibling-package-unchanged"]);
    const f = r.findings.find((x) => x.code === "sibling-package-unchanged");
    expect(f?.message).toContain("Maven/a:api");
    expect(f?.message).toContain("Maven/a:server");
    expect(f?.after).toEqual(["Maven/a:server"]);
    expect(f?.why).toMatch(/fix/);
  });

  it("gives one finding listing every package left out", () => {
    const r = diff(
      record(entry("a:one", OPEN, { known: "< 2" }), entry("a:two", OPEN, { known: "< 2" }), entry("a:three", OPEN, { known: "< 2" })),
      record(entry("a:one", fixedAt("2")), entry("a:two", OPEN, { known: "< 2" }), entry("a:three", OPEN, { known: "< 2" })),
    );
    const found = r.findings.filter((x) => x.code === "sibling-package-unchanged");
    expect(found).toHaveLength(1);
    expect(found[0]?.after).toEqual(["Maven/a:three", "Maven/a:two"]);
  });

  it("applies to ordinary ranges too", () => {
    const r = diff(
      record(entry("a:one", lastAt("1.0.0")), entry("a:two", lastAt("1.0.0"))),
      record(entry("a:one", fixedAt("1.0.1")), entry("a:two", lastAt("1.0.0"))),
    );
    expect(reviewCodes(r).sort()).toEqual(["range-bound-converted", "sibling-package-unchanged"]);
  });

  it("does not depend on array order", () => {
    const b = [entry("a:one", OPEN, { known: "< 2" }), entry("a:two", OPEN, { known: "< 2" }), entry("a:three", OPEN, { known: "< 2" })];
    const a = [entry("a:one", fixedAt("2")), entry("a:two", fixedAt("2")), entry("a:three", OPEN, { known: "< 2" })];
    const pick = (x: JsonObject[], y: JsonObject[]) =>
      diff(record(...x), record(...y)).findings.filter((f) => f.code === "sibling-package-unchanged").map((f) => [f.message, f.after, f.path]);
    expect(pick([...b].reverse(), a)).toEqual(pick(b, a));
    expect(pick(b, [...a].reverse())).toEqual(pick(b, a));
  });

  it("can be allowed, and that does not clear the change itself", () => {
    const b = record(entry("a:one", OPEN, { known: "< 2" }), entry("a:two", OPEN, { known: "< 2" }));
    const a = record(entry("a:one", fixedAt("2")), entry("a:two", OPEN, { known: "< 2" }));
    expect(diff(b, a, ["sibling-package-unchanged"]).status).toBe("review");
    expect(diff(b, a, ["sibling-package-unchanged", "known-range-converted"]).status).toBe("clean");
  });

  it.each([
    ["every package changed", [entry("a:one", lastAt("1")), entry("a:two", lastAt("1"))], [entry("a:one", fixedAt("2")), entry("a:two", fixedAt("2"))]],
    ["the two changed differently", [entry("a:one", lastAt("1")), entry("a:two", lastAt("1"))], [entry("a:one", fixedAt("2")), entry("a:two", fixedAt("3"))]],
    ["the ranges differed before", [entry("a:one", lastAt("1")), entry("a:two", lastAt("2"))], [entry("a:one", fixedAt("2")), entry("a:two", lastAt("2"))]],
    ["the known ranges differed before", [entry("a:one", OPEN, { known: "< 1" }), entry("a:two", OPEN, { known: "< 2" })], [entry("a:one", fixedAt("1")), entry("a:two", OPEN, { known: "< 2" })]],
    ["a single package", [entry("a:one", lastAt("1"))], [entry("a:one", fixedAt("2"))]],
    ["nothing changed", [entry("a:one", lastAt("1")), entry("a:two", lastAt("1"))], [entry("a:one", lastAt("1")), entry("a:two", lastAt("1"))]],
    ["only a reference changed", [entry("a:one", lastAt("1"), { extra: { note: "x" } }), entry("a:two", lastAt("1"))], [entry("a:one", lastAt("1"), { extra: { note: "y" } }), entry("a:two", lastAt("1"))]],
    ["a package was only added", [entry("a:one", lastAt("1"))], [entry("a:one", lastAt("1")), entry("a:new", lastAt("1"), { ecosystem: "npm" })]],
    ["two entries for one package", [entry("a:one", lastAt("1")), entry("a:one", lastAt("1"))], [entry("a:one", fixedAt("2")), entry("a:one", lastAt("1"))]],
  ])("stays quiet when %s", (_name, b, a) => {
    expect(codes(diff(record(...b), record(...a)))).not.toContain("sibling-package-unchanged");
  });

  it("stays quiet when only a known range note left one package and its ranges did not change", () => {
    const r = diff(
      record(entry("a:one", fixedAt("2"), { known: "<= 1" }), entry("a:two", fixedAt("2"), { known: "<= 1" })),
      record(entry("a:one", fixedAt("2")), entry("a:two", fixedAt("2"), { known: "<= 1" })),
    );
    expect(codes(r)).not.toContain("sibling-package-unchanged");
    expect(reviewCodes(r)).toEqual(["known-range-removed"]);
  });

  it("counts a package whose note changed but whose ranges did not as left out", () => {
    const r = diff(
      record(entry("a:one", OPEN, { known: "< 2" }), entry("a:two", OPEN, { known: "< 2" })),
      record(entry("a:one", fixedAt("2")), entry("a:two", OPEN)),
    );
    const f = r.findings.find((x) => x.code === "sibling-package-unchanged");
    expect(f?.after).toEqual(["Maven/a:two"]);
  });

  it("stays quiet when the packages have no version data to compare", () => {
    const bare = (name: string): JsonObject => ({ package: { ecosystem: "Maven", name }, versions: ["1.0.0"] }) as JsonObject;
    const r = diff(record(bare("a:one"), bare("a:two")), record(entry("a:one", lastAt("1")), bare("a:two")));
    expect(codes(r)).not.toContain("sibling-package-unchanged");
  });

  it("stays quiet about an entry with no package", () => {
    const c1 = "1".repeat(40);
    const c2 = "2".repeat(40);
    const ranges = (events: JsonObject[]): JsonObject[] => [{ type: "GIT", repo: "https://example.test/r", events }] as unknown as JsonObject[];
    const bare = (events: JsonObject[]): JsonObject => ({ ranges: ranges(events) }) as JsonObject;
    const named = (events: JsonObject[]): JsonObject => entry("a:two", events, { extra: { ranges: ranges(events) } });
    // The entries have identical ranges, so only the missing package keeps the bare one from being named.
    const r = diff(record(bare(lastAt(c1)), named(lastAt(c1))), record(bare(lastAt(c1)), named(fixedAt(c2))));
    expect(reviewCodes(r)).toContain("range-bound-converted");
    expect(codes(r)).not.toContain("sibling-package-unchanged");
  });

  it("stays small for a very long list of packages", () => {
    const names = Array.from({ length: 3000 }, (_, i) => `g:p${i}`);
    const r = diff(
      record(...names.map((n) => entry(n, lastAt("1")))),
      record(...names.map((n, i) => entry(n, i === 0 ? fixedAt("2") : lastAt("1")))),
    );
    const found = r.findings.filter((x) => x.code === "sibling-package-unchanged");
    expect(found).toHaveLength(1);
    expect(found[0]?.message.length).toBeLessThan(600);
    expect(found[0]?.after).toHaveLength(2999);
  });
});

describe("version spelling in validate", () => {
  const warned = (events: JsonObject[], opts: EntryOptions = {}): string[] => {
    const v = validateText(JSON.stringify(record(entry("pkg", events, opts))));
    expect(v.valid).toBe(true);
    return v.findings.filter((f) => f.code === "version-leading-zero").map((f) => f.message);
  };

  it.each([
    ["fixed", [{ introduced: "0" }, { fixed: "2025.08.14" }], "2025.8.14"],
    ["last_affected", [{ introduced: "0" }, { last_affected: "20260509.0340.15" }], "20260509.340.15"],
    ["introduced", [{ introduced: "01.2.3" }], "1.2.3"],
    ["a v prefix", [{ introduced: "0" }, { fixed: "v1.02.3" }], "v1.2.3"],
    ["a pre-release", [{ introduced: "0" }, { fixed: "1.02.3-rc.1" }], "1.2.3-rc.1"],
  ])("warns on npm: %s", (_name, events, suggestion) => {
    const m = warned(events as unknown as JsonObject[], { ecosystem: "npm" });
    expect(m).toHaveLength(1);
    expect(m[0]).toContain(suggestion);
  });

  it("warns for a SEMVER range in any ecosystem", () => {
    expect(warned(fixedAt("1.02.3"), { ecosystem: "PyPI", type: "SEMVER" })).toHaveLength(1);
  });

  it.each([
    ["a clean npm version", fixedAt("2025.8.14"), { ecosystem: "npm" }],
    ["zero parts", [{ introduced: "0" }, { fixed: "0.0.0" }, { introduced: "1.0.0" }, { fixed: "1.10.0" }], { ecosystem: "npm" }],
    ["a pre-release with leading zeros of its own", fixedAt("1.2.3-01"), { ecosystem: "npm" }],
    ["an ecosystem that allows them", fixedAt("1.02.3"), { ecosystem: "PyPI" }],
    ["a date-like Go pseudo-version part", fixedAt("0.0.0-20230102150405-0123456789ab"), { ecosystem: "Go" }],
  ])("stays quiet on %s", (_name, events, opts) => {
    expect(warned(events as JsonObject[], opts as EntryOptions)).toEqual([]);
  });

  it("stays quiet for a GIT range on an npm package", () => {
    // All digits with a leading zero, so only the range type keeps it from looking like a misspelled version.
    const commit = "0123456789012345678901234567890123456789";
    const ranges = [{ type: "GIT", repo: "https://example.test/r", events: fixedAt(commit) }];
    expect(warned(fixedAt(commit), { ecosystem: "npm", extra: { ranges } })).toEqual([]);
  });

  it("is a warning, so validate still exits 0", () => {
    const p = join(tmp, "spelling.json");
    writeFileSync(p, JSON.stringify(record(entry("pkg", fixedAt("2025.08.14"), { ecosystem: "npm" }))));
    const r = cli(["validate", p]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("version-leading-zero");
  });
});

describe("version spelling in diff", () => {
  const npm = (v: string): JsonObject => record(entry("pkg", fixedAt(v), { ecosystem: "npm" }));

  it("reports removing leading zeros as a spelling change", () => {
    const r = diff(npm("2025.08.14"), npm("2025.8.14"));
    expect(reviewCodes(r)).toEqual(["version-spelling-changed"]);
    const f = r.findings[0];
    expect(f?.before).toBe("2025.08.14");
    expect(f?.after).toBe("2025.8.14");
    expect(f?.message).toContain("leading zeros removed");
    expect(f?.why).toContain("cannot have leading zeros");
    expect(f?.why).not.toContain("between");
  });

  it("says so when a leading zero is introduced", () => {
    const r = diff(npm("2025.8.14"), npm("2025.08.14"));
    expect(reviewCodes(r)).toEqual(["version-spelling-changed"]);
    expect(r.findings[0]?.message).toContain("leading zeros added");
    expect(r.after.findings.map((f) => f.code)).toContain("version-leading-zero");
  });

  it("does not claim a direction when zeros moved", () => {
    const r = diff(npm("1.02.3"), npm("1.2.03"));
    expect(reviewCodes(r)).toEqual(["version-spelling-changed"]);
    expect(r.findings[0]?.message).toContain("differ only in leading zeros");
  });

  it("uses softer wording where the version scheme allows them", () => {
    const py = (v: string): JsonObject => record(entry("pkg", fixedAt(v), { ecosystem: "PyPI" }));
    const r = diff(py("1.02.3"), py("1.2.3"));
    expect(reviewCodes(r)).toEqual(["version-spelling-changed"]);
    expect(r.findings[0]?.why).toContain("Some version schemes");
  });

  it("applies to last_affected and introduced", () => {
    const m = (e: JsonObject[]): JsonObject => record(entry("pkg", e, { ecosystem: "npm" }));
    expect(reviewCodes(diff(m(lastAt("1.02.0")), m(lastAt("1.2.0"))))).toEqual(["version-spelling-changed"]);
    expect(reviewCodes(diff(m([{ introduced: "01.0.0" }]), m([{ introduced: "1.0.0" }])))).toEqual(["version-spelling-changed"]);
  });

  it.each([
    ["a real version change", "1.2.0", "1.3.0"],
    ["a different number of parts", "1.2", "1.2.0"],
    ["a v prefix", "v1.2.3", "1.2.3"],
    ["a pre-release difference", "1.2.3-01", "1.2.3-1"],
    ["a build difference", "1.02.3+a", "1.2.3+b"],
    ["removing a zero that changes the number", "1.20.0", "1.2.0"],
  ])("leaves %s as an ordinary change", (_name, x, y) => {
    expect(reviewCodes(diff(npm(x), npm(y)))).toEqual(["range-event-changed"]);
  });

  it("leaves GIT commits alone", () => {
    const git = (c: string): JsonObject => record({ ranges: [{ type: "GIT", repo: "https://example.test/r", events: [{ introduced: "0" }, { fixed: c }] }] } as JsonObject);
    expect(reviewCodes(diff(git("0123"), git("123")))).toEqual(["range-event-changed"]);
  });

  it("needs its own code in an allow list", () => {
    expect(diff(npm("2025.08.14"), npm("2025.8.14"), ["version-spelling-changed"]).status).toBe("clean");
    expect(diff(npm("2025.08.14"), npm("2025.8.14"), ["range-event-changed"]).status).toBe("review");
  });
});

describe("the shape of a partly converted multi-package advisory", () => {
  const before = record(entry("dev:api", OPEN, { known: "< 2.1.0" }), entry("dev:server", OPEN, { known: "< 2.1.0" }));
  const after = record(entry("dev:api", fixedAt("2.1.0")), entry("dev:server", OPEN, { known: "< 2.1.0" }));

  it("prints a report that names the left-out package", () => {
    const r = diff(before, after);
    const text = renderDiff("before.json", "after.json", r, createStyle(false));
    expect(text).toContain("sibling-package-unchanged");
    expect(text).toContain("Maven/dev:server");
    expect(cliDiff(before, after).code).toBe(1);
  });

  it("has no such finding once every package is converted", () => {
    const all = record(entry("dev:api", fixedAt("2.1.0")), entry("dev:server", fixedAt("2.1.0")));
    const r = diff(before, all);
    expect(reviewCodes(r)).toEqual(["known-range-converted", "known-range-converted"]);
  });
});
