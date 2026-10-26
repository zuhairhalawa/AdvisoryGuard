import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { validateText } from "../src/core/analyze.js";
import { AdvisoryIoError, MAX_FILE_BYTES, parseAdvisoryText, readAdvisoryFile } from "../src/core/load.js";

const tmp = mkdtempSync(join(tmpdir(), "advisoryguard-load-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const BOM = String.fromCharCode(0xfeff);
const BS = String.fromCharCode(92);

describe("parseAdvisoryText", () => {
  it("reports malformed JSON with a position", () => {
    const r = parseAdvisoryText('{"id": "X", "modified": }');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.finding.code).toBe("invalid-json");
      expect(r.finding.message).toMatch(/line 1/);
    }
  });

  it("reports line numbers for multi-line input", () => {
    const r = parseAdvisoryText('{\n  "id": "X",\n  "modified": oops\n}');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.finding.message).toMatch(/line 3/);
  });

  it.each([
    ["{'id': 1}", /property name in double quotes.*line 1, column 2/],
    ['{"a" 1}', /expected ":".*column 6/],
    ['{"a": 1,}', /property name.*column 9/],
    ['{"a": [1, 2,]}', /expected a JSON value.*column 13/],
    ['{"a": 1} extra', /after the end.*column 10/],
    ['{"a": "unterminated', /unterminated string/],
    ['{"a": "bad ' + BS + 'q escape"}', /invalid escape/],
    ['{"a": 01}', /expected ","|after the end|expected "}"/],
    ['{"a": [1 2]}', /expected "," or "]".*column 10/],
    ['{"a": tru}', /expected a JSON value/],
    ['{"a": 1', /expected "," or "}" but found end of input/],
  ])("pinpoints the syntax error in %s", (text, expected) => {
    const r = parseAdvisoryText(text);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.finding.message).toMatch(expected);
  });

  it("rejects empty and whitespace-only files", () => {
    for (const t of ["", "   \n\t "]) {
      const r = parseAdvisoryText(t);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.finding.code).toBe("empty-file");
    }
  });

  it.each([["[]", "an array"], ["null", "null"], ['"x"', "a string"], ["42", "a number"]])(
    "rejects non-object top-level value %s",
    (text, kind) => {
      const r = parseAdvisoryText(text);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.finding.code).toBe("not-an-object");
        expect(r.finding.message).toContain(kind);
      }
    },
  );

  it("tolerates a UTF-8 BOM", () => {
    const r = parseAdvisoryText(BOM + '{"id":"X","modified":"2026-01-01T00:00:00Z"}');
    expect(r.ok).toBe(true);
  });

  it("detects duplicate keys (JSON.parse would silently drop the first)", () => {
    const text = '{"id":"X","modified":"2026-01-01T00:00:00Z","severity":[{"type":"CVSS_V3","score":"a"}],"severity":[]}';
    const r = parseAdvisoryText(text);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.duplicateKeys).toEqual([{ path: "$", key: "severity" }]);
    const v = validateText(text);
    expect(v.valid).toBe(false);
    expect(v.findings.some((f) => f.code === "duplicate-key")).toBe(true);
  });

  it("detects duplicate keys in nested objects and arrays", () => {
    const r = parseAdvisoryText('{"affected":[{"package":{"name":"a","name":"b"}}]}');
    expect(r.ok && r.duplicateKeys).toEqual([{ path: "$.affected[0].package", key: "name" }]);
  });

  it("does not report same key in different objects as duplicate", () => {
    const r = parseAdvisoryText('{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}');
    expect(r.ok && r.duplicateKeys).toEqual([]);
  });

  it("handles escaped quotes and braces inside strings when scanning", () => {
    const text = '{"a":"he said ' + BS + '"{' + BS + '" ok","b":"}","a2":1}';
    const r = parseAdvisoryText(text);
    expect(r.ok && r.duplicateKeys).toEqual([]);
  });

  it("rejects absurdly deep nesting instead of crashing", () => {
    const depth = 1000;
    const text = '{"a":' + "[".repeat(depth) + "]".repeat(depth) + "}";
    const r = parseAdvisoryText(text);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.finding.code).toBe("too-deep");
  });

  it("treats __proto__ as an ordinary key without polluting prototypes", () => {
    const r = parseAdvisoryText('{"id":"X","modified":"2026-01-01T00:00:00Z","__proto__":{"polluted":true}}');
    expect(r.ok).toBe(true);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });
});

describe("readAdvisoryFile", () => {
  it("throws AdvisoryIoError for missing files", () => {
    expect(() => readAdvisoryFile(join(tmp, "nope.json"))).toThrow(AdvisoryIoError);
  });

  it("throws AdvisoryIoError for directories", () => {
    const dir = join(tmp, "dir.json");
    mkdirSync(dir);
    expect(() => readAdvisoryFile(dir)).toThrow(/Not a regular file/);
  });

  it("reads regular files and enforces the size limit constant", () => {
    const f = join(tmp, "a.json");
    writeFileSync(f, "{}");
    expect(readAdvisoryFile(f)).toBe("{}");
    expect(MAX_FILE_BYTES).toBeGreaterThan(1024 * 1024);
  });
});
