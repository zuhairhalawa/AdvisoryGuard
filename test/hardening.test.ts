// This file is ASCII-only. Invisible and right-to-left characters are written as escapes so a
// reader can see what each case contains and re-encoding the file cannot change them.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { run } from "../src/cli/main.js";
import type { CliIo } from "../src/cli/main.js";
import type { JsonObject } from "../src/core/types.js";
import { sanitizeForTerminal, stringifyForTerminal } from "../src/core/util.js";
import { validateText } from "../src/index.js";
import { createStyle } from "../src/report/style.js";
import { renderDiff, renderValidate } from "../src/report/text.js";
import { diff } from "./helpers.js";

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
