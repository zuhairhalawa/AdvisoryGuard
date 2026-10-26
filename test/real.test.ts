import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { diffTexts, validateText } from "../src/core/analyze.js";
import { OSV_SCHEMA_FILE, OSV_SCHEMA_SOURCE, loadOsvSchema } from "../src/core/osvSchema.js";
import type { JsonObject } from "../src/core/types.js";
import { FIXTURES } from "./helpers.js";

const REAL = FIXTURES + "real/";
const files = readdirSync(REAL).filter((f) => f.endsWith(".json")).sort();
const docs = new Map<string, JsonObject>(files.map((f) => [f, JSON.parse(readFileSync(REAL + f, "utf8")) as JsonObject]));

function clone(d: JsonObject): any {
  return structuredClone(d);
}

/** Reverse every array and every object's key order: a pure presentation change. */
function reverseDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(reverseDeep).reverse();
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(Object.entries(v as object).map(([k, x]) => [k, reverseDeep(x)]).reverse());
  }
  return v;
}

function run(before: JsonObject, after: unknown) {
  return diffTexts(JSON.stringify(before), JSON.stringify(after));
}

describe("vendored OSV schema integrity", () => {
  it("is the pinned upstream file (sha256) and loads", () => {
    const bytes = readFileSync(OSV_SCHEMA_FILE);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(OSV_SCHEMA_SOURCE.sha256);
    expect(loadOsvSchema()["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
  });

  it("PROVENANCE.json agrees with the constants compiled into the CLI", () => {
    const prov = JSON.parse(readFileSync(new URL("../vendor/osv-schema/PROVENANCE.json", import.meta.url), "utf8"));
    expect(prov).toMatchObject({
      tag: OSV_SCHEMA_SOURCE.tag,
      commit: OSV_SCHEMA_SOURCE.commit,
      sha256: OSV_SCHEMA_SOURCE.sha256,
      license: "Apache-2.0",
      modified: false,
    });
  });

  it("ships the Apache-2.0 license text next to the schema", () => {
    const text = readFileSync(new URL("../vendor/osv-schema/LICENSE", import.meta.url), "utf8");
    expect(text).toContain("Apache License");
    expect(text).toContain("Version 2.0");
  });
});

describe("genuine GitHub advisories: no false positives", () => {
  it("has a representative, non-trivial fixture set", () => {
    expect(files.length).toBeGreaterThanOrEqual(10);
    const all = [...docs.values()];
    expect(all.some((d) => ((d["severity"] as any[]) ?? []).map((s) => s.type).sort().join() === "CVSS_V3,CVSS_V4")).toBe(true);
    expect(all.some((d) => ((d["affected"] as any[]) ?? []).length >= 8)).toBe(true);
    expect(all.some((d) => d["withdrawn"] !== undefined)).toBe(true);
    expect(all.some((d) => (d["database_specific"] as any)?.github_reviewed === false)).toBe(true);
    expect(all.some((d) => ((d["affected"] as any[]) ?? []).some((a) => a.versions?.length))).toBe(true);
    expect(all.some((d) => ((d["affected"] as any[]) ?? []).some((a) => a.ranges?.some((r: any) => r.events.some((e: any) => e.last_affected))))).toBe(true);
    const ecosystems = new Set(all.flatMap((d) => ((d["affected"] as any[]) ?? []).map((a) => a.package.ecosystem)));
    expect(ecosystems.size).toBeGreaterThanOrEqual(5);
  });

  it.each(files)("%s validates against the official schema with zero errors", (f) => {
    const r = validateText(readFileSync(REAL + f, "utf8"));
    expect(r.findings.filter((x) => x.level === "error")).toEqual([]);
    expect(r.valid).toBe(true);
  });

  it("only produces the expected warnings on these records", () => {
    const seen = new Set<string>();
    for (const f of files) validateText(readFileSync(REAL + f, "utf8")).findings.forEach((x) => seen.add(`${x.level}:${x.code}`));
    // no-severity: unreviewed record without CVSS; invalid-url: genuine record with a scheme-less reference URL
    expect([...seen].sort()).toEqual(["warning:invalid-url", "warning:no-severity"].filter((x) => seen.has(x)));
  });

  it.each(files)("%s: diffing a record against itself, re-serialized and fully reordered, is clean", (f) => {
    const d = docs.get(f) as JsonObject;
    const r = run(d, reverseDeep(d));
    expect(r.findings).toEqual([]);
    expect(r.identical).toBe(true);
    expect(r.status).toBe("clean");
  });

  it.each(files)("%s: an updated modified timestamp alone never needs review", (f) => {
    const d = clone(docs.get(f) as JsonObject);
    d.modified = "2099-01-01T00:00:00Z";
    const r = run(docs.get(f) as JsonObject, d);
    expect(r.findings.map((x) => x.code)).toEqual(["modified-updated"]);
    expect(r.status).toBe("clean");
  });

  it.each(files)("%s: adding a reference / alias / CWE is informational only", (f) => {
    const d = clone(docs.get(f) as JsonObject);
    d.references = [...(d.references ?? []), { type: "WEB", url: "https://example.com/new-write-up" }];
    d.aliases = [...(d.aliases ?? []), "CVE-2099-0001"];
    d.database_specific = { ...(d.database_specific ?? {}), cwe_ids: [...(d.database_specific?.cwe_ids ?? []), "CWE-1"] };
    const r = run(docs.get(f) as JsonObject, d);
    expect(r.status).toBe("clean");
    expect(r.findings.every((x) => x.level === "info")).toBe(true);
  });
});

describe("genuine GitHub advisories: no false negatives (injected mistakes are caught)", () => {
  it.each(files)("%s: deleting every CVSS entry is reported once per entry", (f) => {
    const orig = docs.get(f) as JsonObject;
    const n = ((orig["severity"] as unknown[]) ?? []).length;
    if (n === 0) return;
    const d = clone(orig);
    delete d.severity;
    const r = run(orig, d);
    expect(r.findings.filter((x) => x.code === "severity-removed")).toHaveLength(n);
    expect(r.status).toBe("review");
  });

  it.each(files)("%s: deleting only CVSS v3 or only v4 is reported for exactly that version", (f) => {
    const orig = docs.get(f) as JsonObject;
    for (const type of ["CVSS_V3", "CVSS_V4"]) {
      const sev = ((orig["severity"] as any[]) ?? []);
      if (!sev.some((s) => s.type === type)) continue;
      const d = clone(orig);
      d.severity = sev.filter((s) => s.type !== type);
      const removed = run(orig, d).findings.filter((x) => x.code === "severity-removed");
      expect(removed.map((x) => x.path)).toEqual([`severity[${type}]`]);
    }
  });

  it.each(files)("%s: the original UI bug (fix a package name, lose CVSS) reports both problems", (f) => {
    const orig = docs.get(f) as JsonObject;
    const hasSev = ((orig["severity"] as unknown[]) ?? []).length > 0;
    const affected = (orig["affected"] as any[]) ?? [];
    if (!hasSev || affected.length === 0) return;
    const d = clone(orig);
    d.affected[0].package.name = d.affected[0].package.name + "-fixed";
    delete d.severity;
    const codes = run(orig, d).findings.filter((x) => x.level === "review").map((x) => x.code);
    expect(codes).toContain("package-renamed");
    expect(codes).toContain("severity-removed");
    expect(codes.filter((c) => c === "package-renamed")).toHaveLength(1);
  });

  it.each(files)("%s: a package-name correction alone is exactly one review item", (f) => {
    const orig = docs.get(f) as JsonObject;
    const affected = (orig["affected"] as any[]) ?? [];
    if (affected.length === 0) return;
    const d = clone(orig);
    d.affected[0].package.name = d.affected[0].package.name + "-fixed";
    const r = run(orig, d);
    expect(r.findings.map((x) => x.code)).toEqual(["package-renamed"]);
  });

  it.each(files)("%s: removing a fixed/last_affected event, a range, a package, a reference, an alias or a CWE is flagged", (f) => {
    const orig = docs.get(f) as JsonObject;
    const affected = (orig["affected"] as any[]) ?? [];

    const ev = affected.findIndex((a) => a.ranges?.some((r: any) => r.events.some((e: any) => e.fixed !== undefined)));
    if (ev >= 0) {
      const d = clone(orig);
      const range = d.affected[ev].ranges.find((r: any) => r.events.some((e: any) => e.fixed !== undefined));
      range.events = range.events.filter((e: any) => e.fixed === undefined);
      expect(run(orig, d).findings.map((x) => x.code)).toContain("range-event-removed");
    }
    if (affected.length > 1) {
      const d = clone(orig);
      d.affected.pop();
      expect(run(orig, d).findings.map((x) => x.code)).toContain("package-removed");
    }
    if (((orig["references"] as unknown[]) ?? []).length > 0) {
      const d = clone(orig);
      d.references.pop();
      expect(run(orig, d).findings.map((x) => x.code)).toEqual(["reference-removed"]);
    }
    if (((orig["aliases"] as unknown[]) ?? []).length > 0) {
      const d = clone(orig);
      d.aliases.pop();
      expect(run(orig, d).findings.map((x) => x.code)).toEqual(["alias-removed"]);
    }
    const cwes = (orig["database_specific"] as any)?.cwe_ids ?? [];
    if (cwes.length > 0) {
      const d = clone(orig);
      d.database_specific.cwe_ids = cwes.slice(1);
      expect(run(orig, d).findings.map((x) => x.code)).toEqual(["cwe-removed"]);
    }
  });

  it.each(files)("%s: changing a fixed version is flagged as a change, not as removal+addition of packages", (f) => {
    const orig = docs.get(f) as JsonObject;
    const affected = (orig["affected"] as any[]) ?? [];
    const idx = affected.findIndex((a) => a.ranges?.some((r: any) => r.events.some((e: any) => e.fixed !== undefined)));
    if (idx < 0) return;
    const d = clone(orig);
    const ev = d.affected[idx].ranges.flatMap((r: any) => r.events).find((e: any) => e.fixed !== undefined);
    ev.fixed = ev.fixed + ".1";
    const codes = run(orig, d).findings.map((x) => x.code);
    expect(codes).toEqual(["range-event-changed"]);
  });

  it.each(files)("%s: corrupting the record makes it invalid with a specific, located error", (f) => {
    const orig = docs.get(f) as JsonObject;
    const cases: [string, (d: any) => void, string][] = [
      ["delete id", (d) => delete d.id, "missing-required-field"],
      ["bad timestamp", (d) => (d.modified = "2026-13-45T00:00:00Z"), "invalid-timestamp"],
      ["top-level extra field", (d) => (d.owner = "me"), "unknown-top-level-field"],
      ["bad id prefix", (d) => (d.id = "NOPE-1"), "invalid-id-prefix"],
    ];
    if (((orig["severity"] as unknown[]) ?? []).length > 0) {
      cases.push(["broken CVSS", (d) => (d.severity[0].score = "CVSS:3.1/AV:N"), "invalid-cvss-vector"]);
    }
    if (((orig["affected"] as unknown[]) ?? []).length > 0) {
      cases.push(["bad ecosystem", (d) => (d.affected[0].package.ecosystem = "npmm"), "unknown-ecosystem"]);
      const withRanges = ((orig["affected"] as any[]) ?? []).findIndex((a) => a.ranges?.length > 0);
      if (withRanges >= 0) {
        cases.push(["range without introduced", (d) => (d.affected[withRanges].ranges[0].events = [{ fixed: "9" }]), "range-missing-introduced"]);
      }
    }
    for (const [name, mutate, code] of cases) {
      const d = clone(orig);
      mutate(d);
      const r = validateText(JSON.stringify(d));
      expect(r.valid, `${f}: ${name}`).toBe(false);
      expect(r.findings.some((x) => x.code === code && x.level === "error"), `${f}: ${name} -> ${code}`).toBe(true);
    }
  });
});
