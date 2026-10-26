import { canonicalCvss, cvss3BaseScore, cvss3Rating, diffCvssMetrics, parseCvss } from "../cvss.js";
import type { ParsedCvss } from "../cvss.js";
import { pairItems } from "../pairing.js";
import type { Finding, JsonValue } from "../types.js";
import { asObjectArray, getOwn, isString, shorten } from "../util.js";

interface SevEntry {
  type: string;
  score: string;
  parsed: ParsedCvss | null;
  /** Value used for equality: canonical vector when parseable, else trimmed raw text. */
  key: string;
}

function toEntries(v: JsonValue | undefined): SevEntry[] {
  return asObjectArray(v).map((o) => {
    const typeV = getOwn(o, "type");
    const scoreV = getOwn(o, "score");
    const type = isString(typeV) ? typeV : "(missing type)";
    const score = isString(scoreV) ? scoreV : "";
    const r = score ? parseCvss(score) : null;
    const parsed = r && r.ok ? r.value : null;
    return { type, score, parsed, key: parsed ? canonicalCvss(parsed) : score.trim() };
  });
}

export function describeScore(e: { type: string; score: string; parsed: ParsedCvss | null }): string {
  if (e.score === "") return "(empty)";
  const base = e.parsed ? cvss3BaseScore(e.parsed) : null;
  return base === null ? e.score : `${e.score} (base score ${base.toFixed(1)}, ${cvss3Rating(base)})`;
}

function metricSummary(a: ParsedCvss, b: ParsedCvss): string {
  const deltas = diffCvssMetrics(a, b);
  const parts = deltas.map((d) => `${d.metric}: ${d.before ?? "unset"} -> ${d.after ?? "unset"}`);
  const shown = parts.slice(0, 8).join(", ");
  return parts.length > 8 ? `${shown}, and ${parts.length - 8} more` : shown;
}

const REMOVED_WHY =
  "A CVSS entry is what scanners and Dependabot use to rate this advisory. Editing an unrelated field (such as a package name) should never delete it. If the removal is not intentional, restore the entry.";

/**
 * Compare two `severity` arrays. Entries are matched by `type` (CVSS_V3, CVSS_V4, ...)
 * so multiple severity entries are never conflated, and order is irrelevant.
 *
 * @param basePath   e.g. `severity` or `affected[npm/foo].severity`
 * @param scopeLabel optional text appended to messages, e.g. ` (package npm/foo)`
 */
export function diffSeverity(
  before: JsonValue | undefined,
  after: JsonValue | undefined,
  basePath: string,
  scopeLabel: string,
  out: Finding[],
): void {
  const bs = toEntries(before);
  const as = toEntries(after);
  const { pairs, restB, restA } = pairItems(
    bs,
    as,
    (b) => `${b.type}|${b.key}`,
    (a) => `${a.type}|${a.key}`,
    (b, a) => (b.type === a.type ? 0 : -1),
  );

  for (const { bi, ai, exact } of pairs) {
    if (exact) continue;
    const b = bs[bi];
    const a = as[ai];
    if (!b || !a) continue;
    const path = `${basePath}[${b.type}]`;
    let detail: string;
    if (b.parsed && a.parsed) {
      const versionNote = b.parsed.version !== a.parsed.version ? `version ${b.parsed.version} -> ${a.parsed.version}; ` : "";
      detail = `${versionNote}${metricSummary(b.parsed, a.parsed)}`.replace(/; $/, "");
    } else {
      detail = a.score === "" ? "the new score is empty or missing" : "the new value is not a parseable CVSS vector";
    }
    out.push({
      code: "severity-changed",
      level: "review",
      path,
      message: `${b.type} severity changed${scopeLabel}: ${detail}. Before: ${describeScore(b)}. After: ${describeScore(a)}.`,
      why: "Re-scoring is sometimes legitimate (new analysis, corrected metrics), but it changes how urgently consumers treat this advisory. Confirm the new vector is deliberate.",
      before: shorten(b.score, 200),
      after: shorten(a.score, 200),
    });
  }

  for (const bi of restB) {
    const b = bs[bi];
    if (!b) continue;
    out.push({
      code: "severity-removed",
      level: "review",
      path: `${basePath}[${b.type}]`,
      message: `${b.type} severity was removed${scopeLabel}: ${describeScore(b)}.`,
      why: REMOVED_WHY,
      before: shorten(b.score, 200),
    });
  }

  for (const ai of restA) {
    const a = as[ai];
    if (!a) continue;
    out.push({
      code: "severity-added",
      level: "info",
      path: `${basePath}[${a.type}]`,
      message: `${a.type} severity was added${scopeLabel}: ${describeScore(a)}.`,
      after: shorten(a.score, 200),
    });
  }
}
