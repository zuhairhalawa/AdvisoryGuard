import { describe, expect, it } from "vitest";
import { validateAdvisory } from "../src/core/validate.js";
import type { Finding } from "../src/core/types.js";
import { base, edit, loadFixture } from "./helpers.js";

function find(findings: Finding[], code: string, path?: string): Finding | undefined {
  return findings.find((f) => f.code === code && (path === undefined || f.path === path));
}

describe("validateAdvisory: valid documents", () => {
  it("accepts the realistic GitHub-style fixture without any findings", () => {
    const r = validateAdvisory(base());
    expect(r.findings).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.schemaVersion).toBe("1.6.0");
  });

  it("accepts a minimal record (id + modified only), with advisory warnings", () => {
    const r = validateAdvisory({ id: "OSV-2026-1", modified: "2026-01-01T00:00:00Z" });
    expect(r.valid).toBe(true);
    expect(r.findings.every((f) => f.level === "warning")).toBe(true);
  });

  it("accepts fractional-second timestamps", () => {
    const r = validateAdvisory(edit((d) => (d.modified = "2026-03-05T14:00:00.123Z")));
    expect(r.valid).toBe(true);
  });

  it("accepts multiple severities of different types, including CVSS v2 and Ubuntu priority", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.severity.push({ type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:P/I:P/A:P" });
        d.severity.push({ type: "Ubuntu", score: "high" });
      }),
    );
    expect(r.valid).toBe(true);
  });

  it("accepts severity placed inside affected[]", () => {
    const r = validateAdvisory(
      edit((d) => {
        delete d.severity;
        d.affected[0].severity = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }];
      }),
    );
    expect(r.valid).toBe(true);
  });

  it("rejects severity at BOTH levels (top-level and affected[]), as the official schema does", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.affected[0].severity = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }];
      }),
    );
    expect(r.valid).toBe(false);
    expect(find(r.findings, "severity-at-both-levels", "affected[0].severity")).toBeDefined();
  });

  it("accepts GIT ranges with repo, SEMVER ranges and affected without package when GIT", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.affected.push({
          ranges: [{ type: "GIT", repo: "https://github.com/acme/parser", events: [{ introduced: "0" }, { fixed: "0123456789abcdef0123456789abcdef01234567" }] }],
        });
        d.affected.push({
          package: { ecosystem: "crates.io", name: "acme" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { last_affected: "1.2.3" }] }],
        });
      }),
    );
    expect(r.valid).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it("accepts ecosystem suffixes such as Debian:12", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.affected[0].package.ecosystem = "Debian:12";
      }),
    );
    expect(find(r.findings, "ecosystem-case-mismatch")).toBeUndefined();
  });

  it("accepts a withdrawn advisory without affected[]", () => {
    const r = validateAdvisory({ id: "GHSA-4xq9-w7rh-c3p2", modified: "2026-01-02T00:00:00Z", withdrawn: "2026-01-02T00:00:00Z" });
    expect(find(r.findings, "no-affected")).toBeUndefined();
    expect(r.valid).toBe(true);
  });

  it("accepts unknown extension data inside database_specific / ecosystem_specific", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.database_specific.something_new = { a: 1 };
        d.affected[0].ecosystem_specific = { x: true };
        d.affected[0].database_specific = { y: [1, 2] };
      }),
    );
    expect(r.valid).toBe(true);
  });

  it("rejects unknown TOP-LEVEL fields (the official schema sets additionalProperties: false)", () => {
    const r = validateAdvisory(edit((d) => (d.something_new = { a: 1 })));
    expect(r.valid).toBe(false);
    expect(find(r.findings, "unknown-top-level-field", "something_new")?.message).toMatch(/database_specific/);
  });

  it("accepts null for the nullable list fields GitHub/OSV may emit", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.aliases = null;
        d.references = null;
        d.severity = null;
        d.affected = null;
        d.database_specific.severity = null;
      }),
    );
    expect(r.valid).toBe(true);
  });

  it("recognises GitHub REST/GraphQL advisory objects and points to the OSV format", () => {
    const r = validateAdvisory({ ghsa_id: "GHSA-4xq9-w7rh-c3p2", cve_id: "CVE-2026-1", html_url: "https://github.com/advisories/GHSA-4xq9-w7rh-c3p2", summary: "x" });
    expect(r.valid).toBe(false);
    expect(find(r.findings, "not-osv-format")?.message).toMatch(/advisory-database/);
  });

  it("rejects ids without a registered database prefix, accepts x_ custom prefixes", () => {
    expect(find(validateAdvisory(edit((d) => (d.id = "TEST-1"))).findings, "invalid-id-prefix", "id")).toBeDefined();
    expect(validateAdvisory(edit((d) => (d.id = "x_internal-42"))).valid).toBe(true);
  });

  it("rejects unknown ecosystems (case-sensitive) with a helpful hint", () => {
    const r = validateAdvisory(edit((d) => (d.affected[1].package.ecosystem = "pypi")));
    expect(r.valid).toBe(false);
    expect(find(r.findings, "unknown-ecosystem", "affected[1].package.ecosystem")?.message).toContain('Did you mean "PyPI"');
    expect(find(validateAdvisory(edit((d) => (d.affected[1].package.ecosystem = "Cobol"))).findings, "unknown-ecosystem")).toBeDefined();
  });

  it("rejects GIT ranges with abbreviated commit hashes and bad credits types", () => {
    const g = validateAdvisory(
      edit((d) =>
        d.affected.push({
          ranges: [{ type: "GIT", repo: "https://github.com/acme/parser", events: [{ introduced: "0" }, { fixed: "abc123" }] }],
        }),
      ),
    );
    expect(g.valid).toBe(false);
    expect(find(g.findings, "invalid-git-commit")).toBeDefined();
    const c = validateAdvisory(edit((d) => (d.credits = [{ name: "Ada", type: "TOOLING" }])));
    expect(find(c.findings, "invalid-value", "credits[0].type")?.message).toContain("TOOL");
  });

  it("rejects Ubuntu severity values outside the allowed list and unknown severity sources", () => {
    const u = validateAdvisory(edit((d) => d.severity.push({ type: "Ubuntu", score: "urgent" })));
    expect(find(u.findings, "invalid-value", "severity[2].score")).toBeDefined();
    const s = validateAdvisory(edit((d) => (d.severity[0].source = "ME")));
    expect(find(s.findings, "invalid-value", "severity[0].source")).toBeDefined();
  });
});

describe("validateAdvisory: invalid documents", () => {
  it("flags missing id and modified", () => {
    const r = validateAdvisory({});
    expect(r.valid).toBe(false);
    expect(find(r.findings, "missing-required-field", "id")).toBeDefined();
    expect(find(r.findings, "missing-required-field", "modified")).toBeDefined();
  });

  it("flags wrong types with the exact path", () => {
    const r = validateAdvisory(edit((d) => (d.affected[1].package.name = 42)));
    expect(find(r.findings, "invalid-type", "affected[1].package.name")).toBeDefined();
  });

  it("flags missing package name / ecosystem", () => {
    const r = validateAdvisory(
      edit((d) => {
        delete d.affected[0].package.name;
      }),
    );
    expect(find(r.findings, "missing-required-field", "affected[0].package.name")).toBeDefined();
  });

  it.each(["2026-03-02", "2026-03-02T10:15:30", "2026-03-02T10:15:30+01:00", "yesterday", "2026-13-02T10:15:30Z", "2026-02-31T10:15:30Z"])(
    "rejects invalid timestamp %s",
    (ts) => {
      const r = validateAdvisory(edit((d) => (d.modified = ts)));
      expect(r.valid).toBe(false);
      expect(find(r.findings, "invalid-timestamp", "modified")).toBeDefined();
    },
  );

  it("rejects CVSS_V3 with an invalid vector", () => {
    const r = validateAdvisory(edit((d) => (d.severity[0].score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")));
    expect(find(r.findings, "invalid-cvss-vector", "severity[0].score")?.message).toContain("A");
    expect(r.valid).toBe(false);
  });

  it("rejects a CVSS v4 vector declared as CVSS_V3 (type/vector mismatch)", () => {
    const r = validateAdvisory(
      edit((d) => (d.severity[0].score = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")),
    );
    expect(find(r.findings, "invalid-cvss-vector")?.message).toMatch(/CVSS 4.0 but CVSS 3.x was expected/);
  });

  it("rejects an empty severity score", () => {
    const r = validateAdvisory(edit((d) => (d.severity[1].score = "")));
    expect(r.valid).toBe(false);
  });

  it("rejects an unknown severity type", () => {
    const r = validateAdvisory(edit((d) => (d.severity[0].type = "CVSS_V9")));
    expect(find(r.findings, "invalid-value", "severity[0].type")).toBeDefined();
  });

  it("rejects an unknown reference type and an invalid URL", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.references[0].type = "BLOG";
        d.references[1].url = "not a url";
      }),
    );
    expect(find(r.findings, "invalid-value", "references[0].type")).toBeDefined();
    expect(find(r.findings, "invalid-url", "references[1].url")).toBeDefined();
  });

  it("rejects javascript: reference URLs", () => {
    const r = validateAdvisory(edit((d) => (d.references[0].url = "javascript:alert(1)")));
    expect(find(r.findings, "unsafe-url-scheme")).toBeDefined();
  });

  it("rejects range events with two keys, unknown keys, or no introduced", () => {
    const two = validateAdvisory(edit((d) => (d.affected[0].ranges[0].events = [{ introduced: "0", fixed: "1" }])));
    expect(find(two.findings, "invalid-event")).toBeDefined();
    const typo = validateAdvisory(edit((d) => (d.affected[0].ranges[0].events = [{ introduced: "0" }, { fixd: "1" }])));
    expect(find(typo.findings, "invalid-event")?.message).toContain("fixd");
    const none = validateAdvisory(edit((d) => (d.affected[0].ranges[0].events = [{ fixed: "1.0.0" }])));
    expect(find(none.findings, "range-missing-introduced")).toBeDefined();
    const empty = validateAdvisory(edit((d) => (d.affected[0].ranges[0].events = [])));
    expect(find(empty.findings, "empty-array")).toBeDefined();
  });

  it("rejects an unknown range type and a GIT range without repo", () => {
    const t = validateAdvisory(edit((d) => (d.affected[0].ranges[0].type = "RANGE")));
    expect(find(t.findings, "invalid-value", "affected[0].ranges[0].type")).toBeDefined();
    const g = validateAdvisory(edit((d) => (d.affected[0].ranges[0].type = "GIT")));
    expect(find(g.findings, "git-range-missing-repo")).toBeDefined();
  });

  it("rejects malformed CWE ids", () => {
    const r = validateAdvisory(edit((d) => (d.database_specific.cwe_ids = ["CWE-79", "79", "cwe-94", "CWE-0"])));
    const bad = r.findings.filter((f) => f.code === "invalid-cwe-id").map((f) => f.path);
    expect(bad).toEqual(["database_specific.cwe_ids[1]", "database_specific.cwe_ids[2]", "database_specific.cwe_ids[3]"]);
  });

  it("rejects cwe_ids that is not an array", () => {
    const r = validateAdvisory(edit((d) => (d.database_specific.cwe_ids = "CWE-79")));
    expect(find(r.findings, "invalid-type", "database_specific.cwe_ids")).toBeDefined();
  });

  it("rejects unsupported / malformed schema_version", () => {
    expect(find(validateAdvisory(edit((d) => (d.schema_version = "2.0.0"))).findings, "unsupported-schema-version")).toBeDefined();
    expect(find(validateAdvisory(edit((d) => (d.schema_version = "0.9.0"))).findings, "unsupported-schema-version")).toBeDefined();
    expect(find(validateAdvisory(edit((d) => (d.schema_version = "one"))).findings, "invalid-schema-version")).toBeDefined();
    expect(find(validateAdvisory(edit((d) => (d.schema_version = 1))).findings, "invalid-type", "schema_version")).toBeDefined();
  });

  it("warns, but stays valid, for a newer minor schema_version", () => {
    const r = validateAdvisory(edit((d) => (d.schema_version = "1.99.0")));
    expect(r.valid).toBe(true);
    expect(find(r.findings, "newer-schema-version")?.level).toBe("warning");
  });
});

describe("validateAdvisory: warnings", () => {
  it("warns when no severity is present", () => {
    const r = validateAdvisory(edit((d) => delete d.severity));
    expect(r.valid).toBe(true);
    expect(find(r.findings, "no-severity")?.level).toBe("warning");
  });

  it("does not warn about severity if it is only inside affected[]", () => {
    const r = validateAdvisory(
      edit((d) => {
        delete d.severity;
        d.affected[0].severity = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }];
      }),
    );
    expect(find(r.findings, "no-severity")).toBeUndefined();
  });

  it("warns for duplicate refs/aliases, alias == id, scheme-less URLs", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.references.push({ ...d.references[0] });
        d.references.push({ type: "WEB", url: "github.com/acme/parser" });
        d.aliases = ["CVE-2026-10001", "CVE-2026-10001", d.id];
      }),
    );
    for (const code of ["duplicate-reference", "duplicate-entry", "alias-is-id", "invalid-url"]) {
      expect(find(r.findings, code)?.level, code).toBe("warning");
    }
    expect(r.valid).toBe(true);
  });

  it("rejects fixed + last_affected in one range (official schema rule)", () => {
    const r = validateAdvisory(edit((d) => d.affected[0].ranges[0].events.push({ last_affected: "2.0.0" })));
    expect(r.valid).toBe(false);
    expect(find(r.findings, "range-fixed-and-last-affected", "affected[0].ranges[0]")).toBeDefined();
  });

  it("does not warn when modified predates published (common in genuine GitHub data)", () => {
    const r = validateAdvisory(edit((d) => (d.modified = "2026-01-01T00:00:00Z")));
    expect(r.findings).toEqual([]);
  });

  it("warns for a malformed GHSA id that still has a valid prefix", () => {
    const r = validateAdvisory(edit((d) => (d.id = "GHSA-aaaa-bbbb-cccc")));
    expect(find(r.findings, "invalid-ghsa-id")).toBeDefined();
    expect(r.valid).toBe(true);
  });

  it("warns for SEMVER ranges with non-semver versions", () => {
    const r = validateAdvisory(
      edit((d) => {
        d.affected[0].ranges[0].type = "SEMVER";
        d.affected[0].ranges[0].events = [{ introduced: "0" }, { fixed: "two point four" }];
      }),
    );
    expect(find(r.findings, "non-semver-version")).toBeDefined();
    expect(r.valid).toBe(true);
  });

  it("warns for affected entries listing no versions at all", () => {
    const r = validateAdvisory(edit((d) => (d.affected[0] = { package: d.affected[0].package })));
    expect(find(r.findings, "affected-no-versions")).toBeDefined();
  });
});

describe("validateAdvisory: purity", () => {
  it("never mutates its input", () => {
    const doc = loadFixture("regression-before.json");
    const snapshot = JSON.stringify(doc);
    validateAdvisory(doc);
    expect(JSON.stringify(doc)).toBe(snapshot);
  });
});
