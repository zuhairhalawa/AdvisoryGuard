/**
 * Minimal CVSS vector parsing/validation (v2, v3.x, v4.0) and CVSS v3 base-score
 * calculation. CVSS v4 scoring needs large lookup tables and is intentionally not
 * computed; v4 vectors are still fully validated and compared metric-by-metric.
 */

export type CvssVersion = "2.0" | "3.0" | "3.1" | "4.0";

export interface ParsedCvss {
  version: CvssVersion;
  metrics: Record<string, string>;
}

export type CvssParseResult = { ok: true; value: ParsedCvss } | { ok: false; error: string };

// metric -> comma separated allowed values
type MetricSpec = Record<string, string>;

const SEP = String.fromCharCode(47);

const V2_BASE: MetricSpec = {
  AV: "L,A,N",
  AC: "H,M,L",
  Au: "M,S,N",
  C: "N,P,C",
  I: "N,P,C",
  A: "N,P,C",
};
const V2_OPTIONAL: MetricSpec = {
  E: "U,POC,F,H,ND",
  RL: "OF,TF,W,U,ND",
  RC: "UC,UR,C,ND",
  CDP: "N,L,LM,MH,H,ND",
  TD: "N,L,M,H,ND",
  CR: "L,M,H,ND",
  IR: "L,M,H,ND",
  AR: "L,M,H,ND",
};

const V3_BASE: MetricSpec = {
  AV: "N,A,L,P",
  AC: "L,H",
  PR: "N,L,H",
  UI: "N,R",
  S: "U,C",
  C: "H,L,N",
  I: "H,L,N",
  A: "H,L,N",
};
const V3_OPTIONAL: MetricSpec = {
  E: "X,H,F,P,U",
  RL: "X,U,W,T,O",
  RC: "X,C,R,U",
  CR: "X,H,M,L",
  IR: "X,H,M,L",
  AR: "X,H,M,L",
  MAV: "X,N,A,L,P",
  MAC: "X,L,H",
  MPR: "X,N,L,H",
  MUI: "X,N,R",
  MS: "X,U,C",
  MC: "X,N,L,H",
  MI: "X,N,L,H",
  MA: "X,N,L,H",
};

const V4_BASE: MetricSpec = {
  AV: "N,A,L,P",
  AC: "L,H",
  AT: "N,P",
  PR: "N,L,H",
  UI: "N,P,A",
  VC: "H,L,N",
  VI: "H,L,N",
  VA: "H,L,N",
  SC: "H,L,N",
  SI: "H,L,N",
  SA: "H,L,N",
};
const V4_OPTIONAL: MetricSpec = {
  E: "X,A,P,U",
  CR: "X,H,M,L",
  IR: "X,H,M,L",
  AR: "X,H,M,L",
  MAV: "X,N,A,L,P",
  MAC: "X,L,H",
  MAT: "X,N,P",
  MPR: "X,N,L,H",
  MUI: "X,N,P,A",
  MVC: "X,H,L,N",
  MVI: "X,H,L,N",
  MVA: "X,H,L,N",
  MSC: "X,H,L,N",
  MSI: "X,S,H,L,N",
  MSA: "X,S,H,L,N",
  S: "X,N,P",
  AU: "X,N,Y",
  R: "X,A,U,I",
  V: "X,D,C",
  RE: "X,L,M,H",
  U: "X,Clear,Green,Amber,Red",
};

function specFor(version: CvssVersion): { base: MetricSpec; optional: MetricSpec } {
  switch (version) {
    case "2.0":
      return { base: V2_BASE, optional: V2_OPTIONAL };
    case "4.0":
      return { base: V4_BASE, optional: V4_OPTIONAL };
    default:
      return { base: V3_BASE, optional: V3_OPTIONAL };
  }
}

const PREFIXES: CvssVersion[] = ["3.0", "3.1", "4.0"];

/** Parse and validate a CVSS vector string. `expected` restricts the major version. */
export function parseCvss(input: string, expected?: "2" | "3" | "4"): CvssParseResult {
  const raw = input.trim();
  if (raw === "") return { ok: false, error: "vector is empty" };
  let version: CvssVersion = "2.0";
  let body = raw;
  const known = PREFIXES.find((v) => raw.startsWith("CVSS:" + v + SEP));
  if (known) {
    version = known;
    body = raw.slice(("CVSS:" + known + SEP).length);
  } else if (raw.toUpperCase().startsWith("CVSS:")) {
    return { ok: false, error: `unsupported or malformed CVSS version prefix in "${raw.slice(0, 20)}"` };
  } else {
    if (body.startsWith("(")) body = body.slice(1);
    if (body.endsWith(")")) body = body.slice(0, -1);
  }
  if (expected && version.charAt(0) !== expected) {
    return { ok: false, error: `vector is CVSS ${version} but CVSS ${expected}.x was expected` };
  }
  const { base, optional } = specFor(version);
  const metrics = new Map<string, string>();
  for (const part of body.split(SEP)) {
    const idx = part.indexOf(":");
    if (idx <= 0 || idx === part.length - 1) {
      return { ok: false, error: `malformed metric "${part}"` };
    }
    const key = part.slice(0, idx);
    const value = part.slice(idx + 1);
    if (metrics.has(key)) return { ok: false, error: `metric ${key} appears more than once` };
    const allowed = Object.hasOwn(base, key) ? base[key] : Object.hasOwn(optional, key) ? optional[key] : undefined;
    if (allowed === undefined) return { ok: false, error: `unknown metric "${key}" for CVSS ${version}` };
    if (!allowed.split(",").includes(value)) {
      return {
        ok: false,
        error: `invalid value "${value}" for metric ${key} (allowed: ${allowed.split(",").join(", ")})`,
      };
    }
    metrics.set(key, value);
  }
  const missing = Object.keys(base).filter((k) => !metrics.has(k));
  if (missing.length > 0) {
    return { ok: false, error: `missing required base metric(s): ${missing.join(", ")}` };
  }
  return { ok: true, value: { version, metrics: Object.fromEntries(metrics) } };
}

/** Stable representation used to compare two vectors regardless of metric order. */
export function canonicalCvss(p: ParsedCvss): string {
  const entries = Object.entries(p.metrics)
    // Metrics explicitly set to "Not Defined" (X) are equivalent to omitting them.
    .filter(([, v]) => v !== "X" && v !== "ND")
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `${p.version}|${entries.map(([k, v]) => `${k}:${v}`).join(SEP)}`;
}

export interface MetricDelta {
  metric: string;
  before: string | undefined;
  after: string | undefined;
}

export function diffCvssMetrics(a: ParsedCvss, b: ParsedCvss): MetricDelta[] {
  const keys = [...new Set([...Object.keys(a.metrics), ...Object.keys(b.metrics)])].sort();
  const out: MetricDelta[] = [];
  for (const k of keys) {
    const x = a.metrics[k];
    const y = b.metrics[k];
    if (x !== y) out.push({ metric: k, before: x, after: y });
  }
  return out;
}

function roundUp31(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function roundUp30(x: number): number {
  return Math.ceil(x * 10) / 10;
}

/** CVSS v3.0/v3.1 base score from the base metrics only. Returns null for other versions. */
export function cvss3BaseScore(p: ParsedCvss): number | null {
  if (p.version !== "3.0" && p.version !== "3.1") return null;
  const m = p.metrics;
  const scopeChanged = m["S"] === "C";
  const avTable: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acTable: Record<string, number> = { L: 0.77, H: 0.44 };
  const prTable: Record<string, number> = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 };
  const uiTable: Record<string, number> = { N: 0.85, R: 0.62 };
  const ciaTable: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const av = avTable[m["AV"] ?? ""];
  const ac = acTable[m["AC"] ?? ""];
  const pr = prTable[m["PR"] ?? ""];
  const ui = uiTable[m["UI"] ?? ""];
  const c = ciaTable[m["C"] ?? ""];
  const i = ciaTable[m["I"] ?? ""];
  const a = ciaTable[m["A"] ?? ""];
  if (av === undefined || ac === undefined || pr === undefined || ui === undefined) return null;
  if (c === undefined || i === undefined || a === undefined) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const round = p.version === "3.1" ? roundUp31 : roundUp30;
  return scopeChanged
    ? round(Math.min(1.08 * (impact + exploitability), 10))
    : round(Math.min(impact + exploitability, 10));
}

export function cvss3Rating(score: number): "None" | "Low" | "Medium" | "High" | "Critical" {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}
