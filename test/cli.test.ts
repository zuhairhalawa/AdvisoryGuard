import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { EXIT, run } from "../src/cli/main.js";
import type { CliIo } from "../src/cli/main.js";
import { base, edit, fixturePath, FIXTURES } from "./helpers.js";

const tmp = mkdtempSync(join(tmpdir(), "advisoryguard-cli-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

interface Run {
  code: number;
  out: string;
  err: string;
}

function cli(args: string[], env: Record<string, string | undefined> = {}, isTTY = false): Run {
  let out = "";
  let err = "";
  const io: CliIo = {
    stdout: { write: (s: string) => ((out += s), true), isTTY },
    stderr: { write: (s: string) => ((err += s), true) },
    env,
  };
  const code = run(args, io);
  return { code, out, err };
}

function write(name: string, content: unknown): string {
  const p = join(tmp, name);
  writeFileSync(p, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  return p;
}

const BEFORE = fixturePath("regression-before.json");
const BUG = fixturePath("regression-after-bug.json");
const GOOD = fixturePath("regression-after-correct.json");
const ESC = String.fromCharCode(27);

describe("validate command", () => {
  it("exit 0 for a valid advisory", () => {
    const r = cli(["validate", BEFORE]);
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("VALID");
    expect(r.err).toBe("");
  });

  it("exit 2 for schema violations", () => {
    const p = write("bad-schema.json", edit((d) => (d.severity[0].score = "CVSS:3.1/AV:N")));
    const r = cli(["validate", p]);
    expect(r.code).toBe(EXIT.INVALID);
    expect(r.out).toContain("INVALID");
    expect(r.out).toContain("invalid-cvss-vector");
  });

  it("exit 2 for malformed JSON, with line information", () => {
    const p = write("malformed.json", '{\n  "id": "X",\n  "modified": \n}');
    const r = cli(["validate", p]);
    expect(r.code).toBe(EXIT.INVALID);
    expect(r.out).toMatch(/Invalid JSON.*line 4/);
  });

  it("exit 2 for unsupported schema versions", () => {
    const p = write("v2.json", edit((d) => (d.schema_version = "2.0.0")));
    const r = cli(["validate", p]);
    expect(r.code).toBe(EXIT.INVALID);
    expect(r.out).toContain("unsupported-schema-version");
  });

  it("exit 3 for a missing file, error on stderr", () => {
    const r = cli(["validate", join(tmp, "missing.json")]);
    expect(r.code).toBe(EXIT.USAGE);
    expect(r.err).toMatch(/File not found/);
    expect(r.out).toBe("");
  });

  it("warnings do not fail validation", () => {
    const p = write("warn.json", edit((d) => delete d.severity));
    const r = cli(["validate", p]);
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("with 1 warning");
  });

  it("--json produces machine readable output", () => {
    const p = write("bad-json-out.json", edit((d) => (d.modified = "nope")));
    const r = cli(["validate", p, "--json"]);
    expect(r.code).toBe(EXIT.INVALID);
    const parsed = JSON.parse(r.out);
    expect(parsed).toMatchObject({ tool: "advisoryguard", command: "validate", valid: false, exitCode: 2, outputSchemaVersion: 1 });
    expect(parsed.findings[0]).toMatchObject({ code: "invalid-timestamp", level: "error", path: "modified" });
    expect(parsed.summary.errors).toBe(1);
  });
});

describe("diff command", () => {
  it("exit 0 and 'semantically identical' for the same advisory", () => {
    const r = cli(["diff", BEFORE, BEFORE]);
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("semantically identical");
  });

  it("a correct package-name fix is a review item (exit 1) but does not report the CVSS entries as lost", () => {
    const r = cli(["diff", BEFORE, GOOD]);
    expect(r.code).toBe(EXIT.REVIEW);
    expect(r.out).toContain("package-renamed");
    expect(r.out).not.toContain("severity-removed");
  });

  it("exit 1 and a clear explanation for the CVSS-deletion regression", () => {
    const r = cli(["diff", BEFORE, BUG]);
    expect(r.code).toBe(EXIT.REVIEW);
    expect(r.out).toContain("severity-removed");
    expect(r.out).toContain("severity[CVSS_V3]");
    expect(r.out).toContain("severity[CVSS_V4]");
    expect(r.out).toContain("REVIEW REQUIRED");
    expect(r.out).toContain("Why:");
  });

  it("exit 0 when only modified changed", () => {
    const p = write("only-modified.json", edit((d) => (d.modified = "2026-05-01T00:00:00Z")));
    const r = cli(["diff", BEFORE, p]);
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("modified-updated");
    expect(r.out).toContain("OK");
  });

  it("exit 2 when the edited advisory is invalid", () => {
    const p = write("after-invalid.json", edit((d) => (d.affected[0].ranges[0].events = [{ fixed: "1" }])));
    const r = cli(["diff", BEFORE, p]);
    expect(r.code).toBe(EXIT.INVALID);
    expect(r.out).toContain("range-missing-introduced");
  });

  it("exit 2 when the edited file is not JSON", () => {
    const p = write("after-garbage.json", "this is not json");
    const r = cli(["diff", BEFORE, p]);
    expect(r.code).toBe(EXIT.INVALID);
    expect(r.out).toContain("Invalid JSON");
  });

  it("exit 3 when a file is missing or arguments are wrong", () => {
    expect(cli(["diff", BEFORE, join(tmp, "nope.json")]).code).toBe(EXIT.USAGE);
    expect(cli(["diff", BEFORE]).code).toBe(EXIT.USAGE);
    expect(cli(["diff", BEFORE, BEFORE, BEFORE]).code).toBe(EXIT.USAGE);
  });

  it("--allow acknowledges intended findings => exit 0", () => {
    const r = cli(["diff", BEFORE, GOOD, "--allow", "package-renamed"]);
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("ALLOWED");
    expect(r.out).toContain("1 acknowledged");
    const r2 = cli(["diff", BEFORE, BUG, "--allow=package-renamed,severity-removed"]);
    expect(r2.code).toBe(EXIT.OK);
  });

  it("--allow does not mask other findings", () => {
    expect(cli(["diff", BEFORE, BUG, "--allow", "package-renamed"]).code).toBe(EXIT.REVIEW);
  });

  it("--fail-on invalid only fails for invalid data", () => {
    expect(cli(["diff", BEFORE, BUG, "--fail-on", "invalid"]).code).toBe(EXIT.OK);
    const p = write("after-invalid2.json", edit((d) => (d.modified = "x")));
    expect(cli(["diff", BEFORE, p, "--fail-on", "invalid"]).code).toBe(EXIT.INVALID);
    expect(cli(["diff", BEFORE, BUG, "--fail-on", "bogus"]).code).toBe(EXIT.USAGE);
  });

  it("--json output contains status, findings and validation sections", () => {
    const r = cli(["diff", BEFORE, BUG, "--format", "json"]);
    expect(r.code).toBe(EXIT.REVIEW);
    const j = JSON.parse(r.out);
    expect(j).toMatchObject({
      tool: "advisoryguard",
      command: "diff",
      status: "review",
      identical: false,
      advisoryId: "GHSA-4xq9-w7rh-c3p2",
      exitCode: 1,
      summary: { review: 3, info: 1, acknowledged: 0 },
    });
    expect(j.findings.map((f: { code: string }) => f.code)).toEqual(
      expect.arrayContaining(["severity-removed", "package-renamed", "modified-updated"]),
    );
    expect(j.validation.after.valid).toBe(true);
    expect(r.out.includes(ESC)).toBe(false);
  });

  it("JSON output is deterministic across runs", () => {
    const a = cli(["diff", BEFORE, BUG, "--json"]).out;
    const b = cli(["diff", BEFORE, BUG, "--json"]).out;
    expect(a).toBe(b);
  });
});

describe("usage handling", () => {
  it("--help and --version exit 0", () => {
    const h = cli(["--help"]);
    expect(h.code).toBe(0);
    expect(h.out).toContain("advisoryguard validate");
    expect(h.out).toContain("never makes network requests");
    const v = cli(["--version"]);
    expect(v.code).toBe(0);
    expect(v.out.trim()).toMatch(/^[0-9]+[.][0-9]+[.][0-9]+/);
  });

  it("no arguments prints usage and exits 3", () => {
    const r = cli([]);
    expect(r.code).toBe(EXIT.USAGE);
    expect(r.err).toContain("Usage:");
  });

  it("unknown command / option / format exits 3", () => {
    expect(cli(["frobnicate", BEFORE]).code).toBe(EXIT.USAGE);
    expect(cli(["validate", BEFORE, "--bogus"]).code).toBe(EXIT.USAGE);
    expect(cli(["validate", BEFORE, "--format", "xml"]).code).toBe(EXIT.USAGE);
  });

  it("usage errors are reported as JSON in --json mode", () => {
    const r = cli(["validate", "--json"]);
    expect(r.code).toBe(EXIT.USAGE);
    expect(JSON.parse(r.out)).toMatchObject({ error: { kind: "usage" }, exitCode: 3 });
  });
});

describe("output safety and color", () => {
  it("never emits ANSI codes when not a TTY, or with NO_COLOR / --no-color", () => {
    expect(cli(["diff", BEFORE, BUG]).out.includes(ESC)).toBe(false);
    expect(cli(["diff", BEFORE, BUG, "--no-color"], {}, true).out.includes(ESC)).toBe(false);
    expect(cli(["diff", BEFORE, BUG], { NO_COLOR: "1" }, true).out.includes(ESC)).toBe(false);
  });

  it("emits ANSI colors on a TTY or with FORCE_COLOR", () => {
    expect(cli(["diff", BEFORE, BUG], {}, true).out.includes(ESC)).toBe(true);
    expect(cli(["diff", BEFORE, BUG], { FORCE_COLOR: "1" }).out.includes(ESC)).toBe(true);
  });

  it("escapes terminal control sequences coming from advisory content", () => {
    const evil = edit((d) => {
      d.aliases.push(ESC + "[2J" + ESC + "]0;pwned" + String.fromCharCode(7));
    }, base());
    const p = write("evil.json", evil);
    const r = cli(["diff", BEFORE, p], {}, true);
    const stripped = r.out.split(ESC + "[").join("");
    expect(stripped.includes(ESC)).toBe(false);
    expect(r.out).toContain("u001b");
  });
});

describe("input safety", () => {
  it("never modifies the input files", () => {
    const names = [BEFORE, BUG, GOOD];
    const hash = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");
    const before = names.map(hash);
    const listing = readdirSync(FIXTURES).sort();
    cli(["diff", BEFORE, BUG]);
    cli(["diff", GOOD, BEFORE, "--json"]);
    cli(["validate", BUG]);
    expect(names.map(hash)).toEqual(before);
    expect(readdirSync(FIXTURES).sort()).toEqual(listing);
  });

  it("does not execute or interpret content from the advisory", () => {
    const hostile = edit((d) => {
      d.summary = "$(touch /tmp/pwned) `rm -rf /` ${process.exit(9)}";
    });
    const p = write("hostile.json", hostile);
    const r = cli(["validate", p]);
    expect(r.code).toBe(EXIT.OK);
  });
});
