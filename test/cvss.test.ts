import { describe, expect, it } from "vitest";
import { canonicalCvss, cvss3BaseScore, cvss3Rating, diffCvssMetrics, parseCvss } from "../src/core/cvss.js";

function parseOk(v: string) {
  const r = parseCvss(v);
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

describe("parseCvss", () => {
  it("parses CVSS 3.1, 3.0 and 4.0 vectors", () => {
    expect(parseOk("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").version).toBe("3.1");
    expect(parseOk("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N").version).toBe("3.0");
    expect(parseOk("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").version).toBe("4.0");
  });

  it("parses legacy CVSS 2 vectors", () => {
    expect(parseOk("AV:N/AC:L/Au:N/C:P/I:P/A:P").version).toBe("2.0");
  });

  it("accepts optional temporal/threat metrics", () => {
    expect(parseCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C").ok).toBe(true);
    expect(parseCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A").ok).toBe(true);
  });

  it.each([
    ["", "empty"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "missing A"],
    ["CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "bad value"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L", "duplicate metric"],
    ["CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/S:U/C:H/I:H/A:H", "v4 metric in v3 vector"],
    ["CVSS:9.9/AV:N", "unknown version"],
    ["CVSS:3.1", "no metrics"],
    ["not a vector", "garbage"],
  ])("rejects invalid vector %j (%s)", (v) => {
    expect(parseCvss(v).ok).toBe(false);
  });

  it("enforces the expected major version", () => {
    const r = parseCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "3");
    expect(r.ok).toBe(false);
  });

  it("does not choke on prototype-like metric names", () => {
    expect(parseCvss("CVSS:3.1/__proto__:x/AV:N").ok).toBe(false);
    expect(parseCvss("CVSS:3.1/constructor:x").ok).toBe(false);
  });
});

describe("CVSS v3 base score", () => {
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"],
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"],
    ["CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, "None"],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"],
  ])("%s => %s (%s)", (vector, score, rating) => {
    const p = parseOk(vector);
    expect(cvss3BaseScore(p)).toBe(score);
    expect(cvss3Rating(score)).toBe(rating);
  });

  it("returns null for CVSS v4 (scoring is intentionally not implemented)", () => {
    expect(cvss3BaseScore(parseOk("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))).toBeNull();
  });
});

describe("canonicalCvss / diffCvssMetrics", () => {
  it("is independent of metric order and ignores Not-Defined metrics", () => {
    const a = parseOk("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    const b = parseOk("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:X");
    expect(canonicalCvss(a)).toBe(canonicalCvss(b));
  });

  it("reports changed metrics", () => {
    const a = parseOk("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    const b = parseOk("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(diffCvssMetrics(a, b)).toEqual([{ metric: "AV", before: "N", after: "L" }]);
  });
});
