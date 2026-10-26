import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { diffTexts } from "../src/core/analyze.js";
import { base, codes, diff, edit, fixturePath, reviewCodes } from "./helpers.js";

const V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

describe("no false positives: edits that must NOT require review", () => {
  it("identical advisories => clean and identical", () => {
    const r = diff(base(), base());
    expect(r.status).toBe("clean");
    expect(r.identical).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it("different JSON formatting / indentation / CRLF is ignored", () => {
    const text = JSON.stringify(base());
    const r = diffTexts(text, JSON.stringify(base(), null, 4).split("\n").join("\r\n"));
    expect(r.status).toBe("clean");
    expect(r.identical).toBe(true);
  });

  it("key order changes are ignored", () => {
    const b = base();
    const reordered = Object.fromEntries(Object.entries(b).reverse());
    const r = diff(b, reordered as typeof b);
    expect(r.identical).toBe(true);
    expect(r.status).toBe("clean");
  });

  it("array reordering (severity, affected, ranges, events, references, aliases, CWE) is ignored", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.severity.reverse();
        d.affected.reverse();
        d.affected.forEach((a: any) => {
          a.ranges.reverse();
          a.ranges.forEach((x: any) => x.events.reverse());
        });
        d.references.reverse();
        d.database_specific.cwe_ids.reverse();
        d.aliases = [...d.aliases].reverse();
      }),
    );
    expect(r.findings).toEqual([]);
    expect(r.identical).toBe(true);
  });

  it("CVSS metric order inside a vector and explicit 'Not Defined' metrics are not changes", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.severity[0].score = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:X";
      }),
    );
    expect(r.findings).toEqual([]);
  });

  it("an updated modified timestamp alone is informational, never a vulnerability", () => {
    const r = diff(base(), edit((d) => (d.modified = "2026-04-01T00:00:00Z")));
    expect(r.status).toBe("clean");
    expect(r.identical).toBe(false);
    expect(codes(r)).toEqual(["modified-updated"]);
    expect(r.findings[0]?.level).toBe("info");
  });

  it("the same modified instant in another notation is formatting only", () => {
    const r = diff(base(), edit((d) => (d.modified = "2026-03-02T10:15:30.000Z")));
    expect(r.findings).toEqual([]);
  });

  it("adding references, aliases, CWEs, severity or details is informational", () => {
    const r = diff(
      edit((d) => {
        delete d.severity;
        d.references.pop();
        d.aliases = [];
        d.database_specific.cwe_ids = ["CWE-94"];
      }),
      base(),
    );
    expect(r.status).toBe("clean");
    expect(reviewCodes(r)).toEqual([]);
    expect(codes(r).sort()).toEqual(
      ["alias-added", "cwe-added", "reference-added", "severity-added", "severity-added"].sort(),
    );
  });

  it("editing summary/details wording is informational", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.summary = "Prototype pollution in @acme/parser allows remote code execution";
        d.details = d.details + "\n\nCredit: reported by a researcher.";
      }),
    );
    expect(r.status).toBe("clean");
    expect(codes(r).sort()).toEqual(["details-changed", "summary-changed"]);
  });

  it("whitespace / line-ending-only changes to details are ignored", () => {
    const r = diff(base(), edit((d) => (d.details = d.details.split("\n").join("\r\n") + "\n")));
    expect(r.findings).toEqual([]);
  });

  it("reference URL differences that are only trailing slash / host case are ignored", () => {
    const r = diff(
      edit((d) => (d.references[3].url = "https://github.com/acme/parser/releases/tag/v2.4.1")),
      edit((d) => (d.references[3].url = "https://GitHub.com/acme/parser/releases/tag/v2.4.1/")),
    );
    expect(r.findings).toEqual([]);
  });

  it("correcting the package name while keeping everything else is exactly one review item", () => {
    const r = diff(base(), edit((d) => (d.affected[0].package.name = "@acme/parser")));
    expect(reviewCodes(r)).toEqual(["package-renamed"]);
    const f = r.findings[0];
    expect(f?.before).toBe("@acme/parsr");
    expect(f?.after).toBe("@acme/parser");
    expect(f?.why).toMatch(/registry/);
    // nothing else (severity, ranges, references) is reported
    expect(codes(r)).toEqual(["package-renamed"]);
  });

  it("renaming one package among several does not disturb the untouched ones", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.affected[1].package.name = "acme_parser";
        d.affected.reverse();
      }),
    );
    expect(codes(r)).toEqual(["package-renamed"]);
    expect(r.findings[0]?.message).toContain("acme_parser");
  });
});

describe("no false negatives: the CVSS deletion class of mistake", () => {
  it("REGRESSION: fixing a package name while the CVSS vectors are silently deleted", () => {
    const r = diffTexts(
      readFileSync(fixturePath("regression-before.json"), "utf8"),
      readFileSync(fixturePath("regression-after-bug.json"), "utf8"),
    );
    expect(r.status).toBe("review");
    expect(reviewCodes(r).sort()).toEqual(["package-renamed", "severity-removed", "severity-removed"]);
    const removed = r.findings.filter((f) => f.code === "severity-removed").map((f) => f.path).sort();
    expect(removed).toEqual(["severity[CVSS_V3]", "severity[CVSS_V4]"]);
    // the document is still valid OSV, so this is a review issue rather than invalid data
    expect(r.after.valid).toBe(true);
    expect(r.findings.find((f) => f.path === "severity[CVSS_V3]")?.message).toMatch(/9\.8, Critical/);
    expect(r.findings.find((f) => f.code === "severity-removed")?.why).toMatch(/restore/);
    expect(codes(r, "info")).toBeDefined();
  });

  it("REGRESSION: the correct fix (same package rename, severities intact, reordered) is only a rename", () => {
    const r = diffTexts(
      readFileSync(fixturePath("regression-before.json"), "utf8"),
      readFileSync(fixturePath("regression-after-correct.json"), "utf8"),
    );
    expect(codes(r).sort()).toEqual(["modified-updated", "package-renamed"]);
    expect(r.after.valid).toBe(true);
  });

  it("missing CVSS v3 only", () => {
    const r = diff(base(), edit((d) => (d.severity = d.severity.filter((s: any) => s.type !== "CVSS_V3"))));
    expect(codes(r)).toEqual(["severity-removed"]);
    expect(r.findings[0]?.path).toBe("severity[CVSS_V3]");
    expect(r.findings[0]?.before).toBe(V3);
  });

  it("missing CVSS v4 only", () => {
    const r = diff(base(), edit((d) => (d.severity = d.severity.filter((s: any) => s.type !== "CVSS_V4"))));
    expect(codes(r)).toEqual(["severity-removed"]);
    expect(r.findings[0]?.path).toBe("severity[CVSS_V4]");
    expect(r.findings[0]?.before).toBe(V4);
  });

  it("whole severity key deleted, or replaced by an empty array", () => {
    for (const mut of [(d: any) => delete d.severity, (d: any) => (d.severity = [])]) {
      const r = diff(base(), edit(mut));
      expect(reviewCodes(r)).toEqual(["severity-removed", "severity-removed"]);
      expect(r.status).toBe("review");
    }
  });

  it("a v3 vector swapped for a v4 one is reported as removal + addition, not as unchanged", () => {
    const r = diff(
      edit((d) => (d.severity = [{ type: "CVSS_V3", score: V3 }])),
      edit((d) => (d.severity = [{ type: "CVSS_V4", score: V4 }])),
    );
    expect(codes(r).sort()).toEqual(["severity-added", "severity-removed"]);
  });

  it("changing a vector is flagged with the metric delta and score change", () => {
    const r = diff(base(), edit((d) => (d.severity[0].score = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")));
    expect(codes(r)).toEqual(["severity-changed"]);
    const msg = r.findings[0]?.message ?? "";
    expect(msg).toContain("AV: N -> L");
    expect(msg).toContain("9.8");
    expect(msg).toContain("8.4");
  });

  it("an emptied severity score is flagged and makes the advisory invalid", () => {
    const r = diff(base(), edit((d) => (d.severity[0].score = "")));
    expect(reviewCodes(r)).toEqual(["severity-changed"]);
    expect(r.status).toBe("invalid");
  });

  it("a v4 vector change is flagged even though v4 scores are not computed", () => {
    const r = diff(base(), edit((d) => (d.severity[1].score = V4.replace("VC:H", "VC:L"))));
    expect(codes(r)).toEqual(["severity-changed"]);
    expect(r.findings[0]?.message).toContain("VC: H -> L");
  });

  it("multiple entries of the same type stay distinct", () => {
    const two = edit((d) => {
      d.severity = [
        { type: "CVSS_V3", score: V3 },
        { type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      ];
    });
    const one = edit((d) => (d.severity = [{ type: "CVSS_V3", score: V3 }]));
    const r = diff(two, one);
    expect(codes(r)).toEqual(["severity-removed"]);
    expect(r.findings[0]?.before).toMatch(/AV:L/);
  });

  it("per-package (affected[].severity) removal is flagged for the right package", () => {
    const withPkgSev = edit((d) => {
      d.affected[1].severity = [{ type: "CVSS_V3", score: V3 }];
    });
    const r = diff(withPkgSev, edit((d) => delete d.affected[1].severity, withPkgSev));
    expect(codes(r)).toEqual(["severity-removed"]);
    expect(r.findings[0]?.path).toBe("affected[PyPI/acme-parser].severity[CVSS_V3]");
  });

  it("GitHub qualitative severity label removal / change is flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => delete d.database_specific.severity)))).toEqual(["github-severity-removed"]);
    expect(reviewCodes(diff(base(), edit((d) => (d.database_specific.severity = "LOW"))))).toEqual(["github-severity-changed"]);
  });

  it("package rename combined with CVSS loss reports both independently", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.affected[0].package.name = "@acme/parser";
        d.severity = d.severity.filter((s: any) => s.type !== "CVSS_V4");
      }),
    );
    expect(reviewCodes(r).sort()).toEqual(["package-renamed", "severity-removed"]);
  });
});

describe("affected packages, ranges and version events", () => {
  it("removal of a whole affected package is flagged", () => {
    const r = diff(base(), edit((d) => d.affected.pop()));
    expect(reviewCodes(r)).toEqual(["package-removed"]);
    expect(r.findings[0]?.message).toContain("PyPI/acme-parser");
  });

  it("addition of a new package is flagged for review", () => {
    const r = diff(base(), edit((d) => d.affected.push({ package: { ecosystem: "npm", name: "other" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] })));
    expect(reviewCodes(r)).toEqual(["package-added"]);
  });

  it("removing a fixed event leaves an open-ended range and explains why", () => {
    const r = diff(base(), edit((d) => (d.affected[0].ranges[0].events = [{ introduced: "0" }])));
    expect(reviewCodes(r)).toEqual(["range-event-removed"]);
    expect(r.findings[0]?.message).toContain('"fixed"');
    expect(r.findings[0]?.why).toMatch(/open-ended/);
  });

  it("changing fixed, introduced and last_affected values is flagged individually", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.affected[0].ranges[0].events = [{ introduced: "1.0.0" }, { fixed: "2.5.0" }];
        d.affected[1].ranges[1].events = [{ introduced: "0.5.0" }, { last_affected: "0.9.0" }];
      }),
    );
    expect(codes(r)).toEqual(["range-event-changed", "range-event-changed", "range-event-changed"]);
    const msgs = r.findings.map((f) => f.message).join("\n");
    expect(msgs).toContain("0 -> 1.0.0");
    expect(msgs).toContain("2.4.1 -> 2.5.0");
    expect(msgs).toContain("0.9.9 -> 0.9.0");
  });

  it("adding an event to a range is flagged", () => {
    const r = diff(base(), edit((d) => d.affected[0].ranges[0].events.push({ introduced: "3.0.0" })));
    expect(codes(r)).toEqual(["range-event-added"]);
  });

  it("only the modified range of a multi-range package is reported", () => {
    const r = diff(base(), edit((d) => (d.affected[1].ranges[0].events[1].fixed = "1.9.4")));
    expect(codes(r)).toEqual(["range-event-changed"]);
    expect(r.findings[0]?.path).toBe("affected[PyPI/acme-parser]");
  });

  it("removing / adding a whole range is flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => d.affected[1].ranges.pop())))).toEqual(["range-removed"]);
    expect(
      reviewCodes(diff(base(), edit((d) => d.affected[1].ranges.push({ type: "ECOSYSTEM", events: [{ introduced: "9.0.0" }] })))),
    ).toEqual(["range-added"]);
  });

  it("explicit versions[] list removals and additions are flagged", () => {
    const withVersions = edit((d) => (d.affected[0].versions = ["1.0.0", "1.1.0", "2.0.0"]));
    const r = diff(withVersions, edit((d) => (d.affected[0].versions = ["1.0.0", "2.0.0", "2.1.0"]), withVersions));
    expect(codes(r).sort()).toEqual(["versions-added", "versions-removed"]);
    expect(diff(withVersions, edit((d) => (d.affected[0].versions = ["2.0.0", "1.1.0", "1.0.0"]), withVersions)).findings).toEqual([]);
  });

  it("ecosystem change on a package is flagged", () => {
    const r = diff(base(), edit((d) => (d.affected[0].package.ecosystem = "PyPI")));
    expect(reviewCodes(r)).toContain("package-ecosystem-changed");
  });

  it("purl removal / change is flagged", () => {
    const withPurl = edit((d) => (d.affected[0].package.purl = "pkg:npm/%40acme/parsr"));
    expect(reviewCodes(diff(withPurl, edit((d) => delete d.affected[0].package.purl, withPurl)))).toEqual(["package-purl-changed"]);
  });

  it("two entries for the same package with different ranges stay distinct", () => {
    const two = edit((d) =>
      d.affected.push({
        package: { ecosystem: "npm", name: "@acme/parsr" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }, { fixed: "3.1.0" }] }],
      }),
    );
    const r = diff(two, edit((d) => (d.affected[2].ranges[0].events[1].fixed = "3.2.0"), two));
    expect(codes(r)).toEqual(["range-event-changed"]);
    expect(r.findings[0]?.message).toContain("3.1.0 -> 3.2.0");
  });

  it("a package with a typo AND changed ranges still pairs up (rename + range change)", () => {
    const r = diff(
      base(),
      edit((d) => {
        d.affected[0].package.name = "@acme/parser";
        d.affected[0].ranges[0].events[1].fixed = "2.4.2";
      }),
    );
    expect(codes(r).sort()).toEqual(["package-renamed", "range-event-changed"]);
  });
});

describe("references, aliases, CWE, text and other metadata", () => {
  it("removed references are flagged individually", () => {
    const r = diff(base(), edit((d) => (d.references = d.references.slice(0, 2))));
    expect(codes(r)).toEqual(["reference-removed", "reference-removed"]);
  });

  it("removing all references is flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => delete d.references)))).toHaveLength(4);
  });

  it("changing a reference's type is informational", () => {
    const r = diff(base(), edit((d) => (d.references[3].type = "ARTICLE")));
    expect(codes(r)).toEqual(["reference-type-changed"]);
    expect(r.status).toBe("clean");
  });

  it("alias removal (CVE link) is flagged", () => {
    const r = diff(base(), edit((d) => delete d.aliases));
    expect(reviewCodes(r)).toEqual(["alias-removed"]);
    expect(r.findings[0]?.why).toMatch(/CVE/);
  });

  it("related / upstream removal is flagged", () => {
    const b = edit((d) => {
      d.related = ["GHSA-aaaa-bbbb-cccc"];
      d.upstream = ["CVE-2026-1"];
    });
    expect(reviewCodes(diff(b, edit((d) => (delete d.related, delete d.upstream), b))).sort()).toEqual(["related-removed", "upstream-removed"]);
  });

  it("CWE removal is flagged, and total removal says so", () => {
    expect(reviewCodes(diff(base(), edit((d) => (d.database_specific.cwe_ids = ["CWE-94"]))))).toEqual(["cwe-removed"]);
    const r = diff(base(), edit((d) => delete d.database_specific.cwe_ids));
    expect(reviewCodes(r)).toEqual(["cwe-removed", "cwe-removed"]);
    expect(r.findings[0]?.message).toMatch(/no CWE is listed/);
  });

  it("summary or details wiped out is flagged; a big truncation of details is flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => delete d.summary)))).toEqual(["summary-removed"]);
    expect(reviewCodes(diff(base(), edit((d) => (d.details = ""))))).toEqual(["details-removed"]);
    expect(reviewCodes(diff(base(), edit((d) => (d.details = d.details.slice(0, 40)))))).toEqual(["details-shortened"]);
  });

  it("id, published and withdrawn changes are flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => (d.id = "GHSA-aaaa-bbbb-cccc"))))).toEqual(["id-changed"]);
    expect(reviewCodes(diff(base(), edit((d) => (d.published = "2025-01-01T00:00:00Z"))))).toEqual(["published-changed"]);
    expect(reviewCodes(diff(base(), edit((d) => (d.withdrawn = "2026-03-10T00:00:00Z"))))).toEqual(["advisory-withdrawn"]);
    const w = edit((d) => (d.withdrawn = "2026-03-10T00:00:00Z"));
    expect(reviewCodes(diff(w, edit((d) => delete d.withdrawn, w)))).toEqual(["withdrawal-reverted"]);
  });

  it("a modified timestamp moving backwards is flagged", () => {
    expect(reviewCodes(diff(base(), edit((d) => (d.modified = "2026-01-01T00:00:00Z"))))).toEqual(["modified-regressed"]);
  });

  it("deleted unknown / GitHub-specific fields are never silently lost", () => {
    const r = diff(base(), edit((d) => (delete d.database_specific.nvd_published_at, delete d.database_specific.github_reviewed)));
    expect(codes(r).sort()).toEqual(["field-removed", "field-removed"]);
    expect(r.findings[0]?.path).toMatch(/^database_specific\./);
  });

  it("deleting an entire top-level extension object is flagged", () => {
    const b = edit((d) => (d.x_custom = { owner: "team-a" }));
    expect(codes(diff(b, edit((d) => delete d.x_custom, b)))).toEqual(["field-removed"]);
  });

  it("credits: removal is flagged, addition is informational", () => {
    const b = edit((d) => (d.credits = [{ name: "Ada", type: "FINDER" }, { name: "Bob", type: "REMEDIATION_DEVELOPER" }]));
    expect(codes(diff(b, edit((d) => d.credits.pop(), b)))).toEqual(["list-item-removed"]);
    expect(codes(diff(edit((d) => d.credits.pop(), b), b))).toEqual(["list-item-added"]);
  });

  it("changed values in security-sensitive unknown fields are reviewed; others are info", () => {
    const b = edit((d) => (d.affected[0].database_specific = { last_known_affected_version_range: "<= 2.4.0", note: "x" }));
    const r = diff(b, edit((d) => (d.affected[0].database_specific = { last_known_affected_version_range: "<= 2.3.0", note: "y" }), b));
    expect(r.findings.map((f) => [f.code, f.level]).sort()).toEqual([
      ["field-changed", "info"],
      ["field-changed", "review"],
    ]);
  });

  it("schema_version change is informational", () => {
    const r = diff(base(), edit((d) => (d.schema_version = "1.7.0")));
    expect(codes(r)).toEqual(["field-changed"]);
    expect(r.status).toBe("clean");
  });
});

describe("status handling and robustness", () => {
  it("invalid 'after' => status invalid even when nothing else changed", () => {
    const r = diff(base(), edit((d) => (d.modified = "bogus")));
    expect(r.status).toBe("invalid");
  });

  it("invalid 'before' alone does not make a good 'after' invalid", () => {
    const r = diff(edit((d) => (d.modified = "bogus")), base());
    expect(r.before.valid).toBe(false);
    expect(r.status).not.toBe("invalid");
  });

  it("unparseable inputs produce an invalid result without throwing", () => {
    const r = diffTexts("{nope", JSON.stringify(base()));
    expect(r.status).toBe("clean");
    expect(r.before.valid).toBe(false);
    const r2 = diffTexts(JSON.stringify(base()), "{nope");
    expect(r2.status).toBe("invalid");
    expect(r2.findings).toEqual([]);
  });

  it("--allow acknowledges intended review findings and restores a clean status", () => {
    const after = edit((d) => (d.affected[0].package.name = "@acme/parser"));
    const r = diffTexts(JSON.stringify(base()), JSON.stringify(after), { allow: ["package-renamed"] });
    expect(r.status).toBe("clean");
    expect(r.acknowledged).toBe(1);
    expect(r.findings[0]?.acknowledged).toBe(true);
    // allowing something else does not hide the finding
    const r2 = diffTexts(JSON.stringify(base()), JSON.stringify(after), { allow: ["severity-removed"] });
    expect(r2.status).toBe("review");
  });

  it("--allow cannot hide invalid data", () => {
    const r = diffTexts(JSON.stringify(base()), JSON.stringify(edit((d) => (d.severity[0].score = ""))), { allow: ["severity-changed"] });
    expect(r.status).toBe("invalid");
  });

  it("is deterministic and does not mutate its inputs", () => {
    const b = base();
    const a = edit((d) => {
      d.affected[0].package.name = "x";
      d.severity.pop();
    });
    const sb = JSON.stringify(b);
    const sa = JSON.stringify(a);
    const r1 = diff(b, a);
    const r2 = diff(b, a);
    expect(JSON.stringify(r1)).toBe(JSON.stringify(r2));
    expect(JSON.stringify(b)).toBe(sb);
    expect(JSON.stringify(a)).toBe(sa);
  });

  it("handles advisories with unusual structure (no affected, non-array fields) without throwing", () => {
    const weird = { id: "X", modified: "2026-01-01T00:00:00Z", affected: "nope", references: 5, severity: {}, aliases: null };
    expect(() => diffTexts(JSON.stringify(weird), JSON.stringify(base()))).not.toThrow();
    expect(() => diffTexts(JSON.stringify(base()), JSON.stringify(weird))).not.toThrow();
    const r = diffTexts(JSON.stringify(base()), JSON.stringify(weird));
    expect(r.status).toBe("invalid");
  });

  it("stays fast on adversarial input: thousands of unmatched packages, ecosystems and list items", () => {
    const n = 4000;
    const mk = (prefix: string, eco: (i: number) => string) =>
      edit((d) => {
        d.affected = Array.from({ length: n }, (_, i) => ({
          package: { ecosystem: eco(i), name: `${prefix}-${i}` },
          versions: [`${i}.0.0`],
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: `${i}.9.0` }] }],
        }));
        d.credits = Array.from({ length: n }, (_, i) => ({ name: `${prefix}-${i}`, type: "FINDER" }));
      });
    const t0 = Date.now();
    const sameEco = diff(mk("a", () => "npm"), mk("b", () => "npm"));
    const uniqueEco = diff(mk("a", (i) => `eco${i}`), mk("b", (i) => `eco${i}`));
    expect(Date.now() - t0).toBeLessThan(15000);
    // Over the pairing limit the entries are reported conservatively as removed/added, with a notice.
    expect(codes(sameEco)).toContain("pairing-limit");
    expect(codes(sameEco).filter((c) => c === "package-removed")).toHaveLength(n);
    expect(codes(sameEco).filter((c) => c === "package-added")).toHaveLength(n);
    expect(sameEco.status).toBe("review");
    // Made-up ecosystems are not valid OSV, so the verdict is "invalid", but every entry is still reported.
    expect(uniqueEco.status).toBe("invalid");
    // One unmatched entry per ecosystem on each side is the "rename" case, found without quadratic work.
    expect(codes(uniqueEco).filter((c) => c === "package-renamed")).toHaveLength(n);
  });

  it("copes with a large advisory (500 packages, 2000 versions) quickly", () => {
    const big = edit((d) => {
      for (let i = 0; i < 500; i++) {
        d.affected.push({
          package: { ecosystem: "npm", name: `pkg-${i}` },
          versions: Array.from({ length: 4 }, (_, k) => `${i}.${k}.0`),
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: `${i}.9.0` }] }],
        });
      }
    });
    const changed = edit((d) => (d.affected[300].ranges[0].events[1].fixed = "9.9.9"), big);
    const t0 = Date.now();
    const r = diff(big, changed);
    expect(codes(r)).toEqual(["range-event-changed"]);
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});
