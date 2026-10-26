import { setMinus } from "../pairing.js";
import type { Finding, JsonObject, JsonValue } from "../types.js";
import { asArray, asObjectArray, getOwn, isObject, isString, shorten } from "../util.js";

const AUTHORITY_PREFIX = "/".repeat(2);

function str(v: JsonValue | undefined): string | undefined {
  return isString(v) ? v : undefined;
}

export function diffId(b: JsonObject, a: JsonObject, out: Finding[]): void {
  const x = str(getOwn(b, "id"));
  const y = str(getOwn(a, "id"));
  if (x !== y) {
    out.push({
      code: "id-changed",
      level: "review",
      path: "id",
      message: `Advisory id changed from ${x ?? "(unset)"} to ${y ?? "(unset)"}.`,
      why: "The id is the primary key of the record; changing it makes this a different advisory in the eyes of every consumer.",
      ...(x !== undefined ? { before: x } : {}),
      ...(y !== undefined ? { after: y } : {}),
    });
  }
}

function time(v: string | undefined): number | null {
  if (v === undefined) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

export function diffTimestamps(b: JsonObject, a: JsonObject, out: Finding[]): void {
  // modified: changing it is the normal consequence of any edit.
  const mb = str(getOwn(b, "modified"));
  const ma = str(getOwn(a, "modified"));
  if (mb !== ma) {
    const tb = time(mb);
    const ta = time(ma);
    if (ma === undefined) {
      out.push({
        code: "modified-removed",
        level: "review",
        path: "modified",
        message: "The modified timestamp was removed.",
        why: "modified is required by the OSV schema and consumers use it to detect updates.",
        ...(mb !== undefined ? { before: mb } : {}),
      });
    } else if (tb !== null && ta !== null && ta < tb) {
      out.push({
        code: "modified-regressed",
        level: "review",
        path: "modified",
        message: `modified moved backwards: ${mb} -> ${ma}.`,
        why: "Consumers use modified to decide whether a record changed; an older timestamp can make the update be ignored.",
        ...(mb !== undefined ? { before: mb } : {}),
        after: ma,
      });
    } else if (tb !== ta) {
      out.push({
        code: "modified-updated",
        level: "info",
        path: "modified",
        message: `modified timestamp updated: ${mb ?? "(unset)"} -> ${ma}. This is expected for any edit and is not a vulnerability change.`,
        ...(mb !== undefined ? { before: mb } : {}),
        after: ma,
      });
    }
    // Same instant with a different textual form (e.g. ".000Z"): formatting only, no finding.
  }

  const pb = str(getOwn(b, "published"));
  const pa = str(getOwn(a, "published"));
  if (pb !== pa && !(time(pb) !== null && time(pb) === time(pa))) {
    if (pb === undefined) {
      out.push({ code: "published-added", level: "info", path: "published", message: `published was set to ${pa}.`, ...(pa !== undefined ? { after: pa } : {}) });
    } else {
      out.push({
        code: "published-changed",
        level: "review",
        path: "published",
        message: pa === undefined ? `published (${pb}) was removed.` : `published changed from ${pb} to ${pa}.`,
        why: "The publication date normally never changes after release; downstream tools use it for reporting and deduplication.",
        before: pb,
        ...(pa !== undefined ? { after: pa } : {}),
      });
    }
  }

  const wb = str(getOwn(b, "withdrawn"));
  const wa = str(getOwn(a, "withdrawn"));
  if (wb !== wa && !(time(wb) !== null && time(wb) === time(wa))) {
    if (wb === undefined) {
      out.push({
        code: "advisory-withdrawn",
        level: "review",
        path: "withdrawn",
        message: `The advisory is now marked as withdrawn (${wa}).`,
        why: "Withdrawing an advisory tells consumers it was a mistake and stops alerts for it. Make sure that is what you want.",
        ...(wa !== undefined ? { after: wa } : {}),
      });
    } else if (wa === undefined) {
      out.push({
        code: "withdrawal-reverted",
        level: "review",
        path: "withdrawn",
        message: `The withdrawn marker (${wb}) was removed; the advisory is active again.`,
        why: "Un-withdrawing re-enables alerts for this advisory.",
        before: wb,
      });
    } else {
      out.push({ code: "withdrawn-changed", level: "info", path: "withdrawn", message: `withdrawn changed from ${wb} to ${wa}.`, before: wb, after: wa });
    }
  }
}

function normalizeUrl(raw: string): string {
  const t = raw.trim();
  try {
    const u = new URL(t);
    u.hash = u.hash === "#" ? "" : u.hash;
    let p = u.pathname;
    if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
    return `${u.protocol}${AUTHORITY_PREFIX}${u.host}${p}${u.search}${u.hash}`;
  } catch {
    return t;
  }
}

interface Ref {
  url: string;
  key: string;
  type: string;
}

function toRefs(v: JsonValue | undefined): Ref[] {
  const refs: Ref[] = [];
  for (const o of asObjectArray(v)) {
    const url = str(getOwn(o, "url"));
    if (url === undefined) continue;
    refs.push({ url, key: normalizeUrl(url), type: str(getOwn(o, "type")) ?? "(no type)" });
  }
  return refs;
}

export function diffReferences(before: JsonValue | undefined, after: JsonValue | undefined, out: Finding[]): void {
  const bs = toRefs(before);
  const as = toRefs(after);
  const bTypes = new Map<string, Set<string>>();
  const aTypes = new Map<string, Set<string>>();
  const add = (m: Map<string, Set<string>>, r: Ref): void => {
    const s = m.get(r.key) ?? new Set<string>();
    s.add(r.type);
    m.set(r.key, s);
  };
  bs.forEach((r) => add(bTypes, r));
  as.forEach((r) => add(aTypes, r));
  const firstUrl = (list: Ref[], key: string): string => list.find((r) => r.key === key)?.url ?? key;

  const keysB = [...bTypes.keys()].sort();
  const keysA = [...aTypes.keys()].sort();
  for (const k of keysB) {
    const types = [...(bTypes.get(k) ?? [])].sort();
    const at = aTypes.get(k);
    if (!at) {
      out.push({
        code: "reference-removed",
        level: "review",
        path: "references",
        message: `Reference removed (${types.join("/")}): ${shorten(firstUrl(bs, k), 160)}`,
        why: "References document the advisory's sources and fixes. Deleting one loses provenance; check it was not dropped as a side effect of another edit.",
        before: firstUrl(bs, k),
      });
    } else {
      const aList = [...at].sort();
      if (aList.join(",") !== types.join(",")) {
        out.push({
          code: "reference-type-changed",
          level: "info",
          path: "references",
          message: `Reference type changed ${types.join("/")} -> ${aList.join("/")}: ${shorten(firstUrl(as, k), 160)}`,
        });
      }
    }
  }
  for (const k of keysA) {
    if (!bTypes.has(k)) {
      out.push({
        code: "reference-added",
        level: "info",
        path: "references",
        message: `Reference added (${[...(aTypes.get(k) ?? [])].sort().join("/")}): ${shorten(firstUrl(as, k), 160)}`,
        after: firstUrl(as, k),
      });
    }
  }
}

function strings(v: JsonValue | undefined): string[] {
  return asArray(v).filter(isString).map((s) => s.trim());
}

const LIST_WHY: Record<string, string> = {
  aliases:
    "Aliases (for example CVE ids) link this record to the same vulnerability in other databases. Removing one breaks cross-referencing and de-duplication.",
  related: "Related ids link this record to other advisories. Removing one loses that relationship.",
  upstream: "Upstream ids record where this vulnerability originated. Removing one loses that provenance.",
};

export function diffIdList(field: "aliases" | "related" | "upstream", b: JsonObject, a: JsonObject, out: Finding[]): void {
  const bv = strings(getOwn(b, field));
  const av = strings(getOwn(a, field));
  const gone = setMinus(bv, av).sort();
  const fresh = setMinus(av, bv).sort();
  const noun = field === "aliases" ? "alias" : field;
  const label = field === "aliases" ? "Alias" : field === "related" ? "Related id" : "Upstream id";
  for (const v of gone) {
    out.push({
      code: `${noun}-removed`,
      level: "review",
      path: field,
      message: `${label} removed: ${shorten(v, 80)}.`,
      why: LIST_WHY[field] ?? "",
      before: v,
    });
  }
  for (const v of fresh) {
    out.push({
      code: `${noun}-added`,
      level: "info",
      path: field,
      message: `${label} added: ${shorten(v, 80)}.`,
      after: v,
    });
  }
}

function dbSpecific(o: JsonObject): JsonObject | undefined {
  const d = getOwn(o, "database_specific");
  return isObject(d) ? d : undefined;
}

export function diffCwe(b: JsonObject, a: JsonObject, out: Finding[]): void {
  const bd = dbSpecific(b);
  const ad = dbSpecific(a);
  const bv = strings(bd ? getOwn(bd, "cwe_ids") : undefined);
  const av = strings(ad ? getOwn(ad, "cwe_ids") : undefined);
  const gone = setMinus(bv, av).sort();
  const fresh = setMinus(av, bv).sort();
  for (const v of gone) {
    out.push({
      code: "cwe-removed",
      level: "review",
      path: "database_specific.cwe_ids",
      message: `CWE removed: ${shorten(v, 40)}${av.length === 0 ? " (no CWE is listed any more)" : ""}.`,
      why: "CWE ids classify the weakness behind the vulnerability. Dropping one is sometimes a legitimate reclassification, but it is also easy to lose by accident.",
      before: v,
    });
  }
  for (const v of fresh) {
    out.push({
      code: "cwe-added",
      level: "info",
      path: "database_specific.cwe_ids",
      message: `CWE added: ${shorten(v, 40)}.`,
      after: v,
    });
  }
}

export function diffGithubSeverity(b: JsonObject, a: JsonObject, out: Finding[]): void {
  const bd = dbSpecific(b);
  const ad = dbSpecific(a);
  const x = bd ? getOwn(bd, "severity") : undefined;
  const y = ad ? getOwn(ad, "severity") : undefined;
  if (JSON.stringify(x) === JSON.stringify(y)) return;
  const path = "database_specific.severity";
  const fmt = (v: JsonValue | undefined): string => (v === undefined ? "(unset)" : JSON.stringify(v));
  if (x === undefined) {
    out.push({ code: "github-severity-added", level: "info", path, message: `GitHub severity label set to ${fmt(y)}.`, ...(y !== undefined ? { after: y } : {}) });
  } else if (y === undefined) {
    out.push({
      code: "github-severity-removed",
      level: "review",
      path,
      message: `GitHub severity label ${fmt(x)} was removed.`,
      why: "GitHub shows this label (LOW/MODERATE/HIGH/CRITICAL) on the advisory page and in alerts; it should not disappear when other fields are edited.",
      before: x,
    });
  } else {
    out.push({
      code: "github-severity-changed",
      level: "review",
      path,
      message: `GitHub severity label changed from ${fmt(x)} to ${fmt(y)}.`,
      why: "The label drives how alerts are prioritised. Make sure it still agrees with the CVSS vector(s).",
      before: x,
      after: y,
    });
  }
}

function norm(s: string): string {
  return s.split("\r\n").join("\n").trim();
}

export function diffText(field: "summary" | "details", b: JsonObject, a: JsonObject, out: Finding[]): void {
  const x = str(getOwn(b, field));
  const y = str(getOwn(a, field));
  const nx = x === undefined ? "" : norm(x);
  const ny = y === undefined ? "" : norm(y);
  if (nx === ny) return;
  if (nx !== "" && ny === "") {
    out.push({
      code: `${field}-removed`,
      level: "review",
      path: field,
      message: `The ${field} text was removed or emptied (${nx.length} characters lost).`,
      why: "Users read this text to understand the vulnerability and how to respond.",
      before: shorten(nx, 200),
    });
    return;
  }
  if (nx === "") {
    out.push({ code: `${field}-added`, level: "info", path: field, message: `${field} was added.`, after: shorten(ny, 200) });
    return;
  }
  if (field === "details" && nx.length >= 200 && ny.length < nx.length / 2) {
    out.push({
      code: "details-shortened",
      level: "review",
      path: field,
      message: `details shrank substantially (${nx.length} -> ${ny.length} characters).`,
      why: "A large drop in length can mean content was truncated or pasted over by accident. (Heuristic: flagged when less than half remains.)",
    });
    return;
  }
  out.push({ code: `${field}-changed`, level: "info", path: field, message: `${field} text was edited (${nx.length} -> ${ny.length} characters).` });
}
