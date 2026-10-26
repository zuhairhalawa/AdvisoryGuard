import { pairItems } from "../pairing.js";
import type { Finding, JsonValue } from "../types.js";
import { canonical, getOwn, hasOwn, isObject, shorten } from "../util.js";

/** Field names whose modification could plausibly affect who is told they are vulnerable. */
const SENSITIVE = /(severity|cwe|cve|fix|patch|affect|version|range|vulnerab|exploit|score|cvss)/i;

/** Only the field's own (last) name counts, so nothing is "sensitive" merely for living under `affected`. */
function isSensitiveKey(path: string): boolean {
  const last = path.replace(/[[][0-9]+[\]]$/, "").split(".").pop() ?? "";
  if (last === "schema_version") return false;
  return SENSITIVE.test(last);
}

function preview(v: JsonValue | undefined): JsonValue | undefined {
  if (typeof v === "string") return shorten(v, 200);
  if (v === undefined) return undefined;
  const s = canonical(v);
  return s.length > 200 ? shorten(s, 200) : v;
}

function show(v: JsonValue | undefined): string {
  if (v === undefined) return "(unset)";
  if (typeof v === "string") return JSON.stringify(shorten(v, 80));
  return shorten(canonical(v), 80);
}

/**
 * Structural comparison for every field that has no dedicated comparer. Guarantees
 * that a deleted value anywhere in the document never goes unnoticed:
 *  - removal of a field / list item  => review
 *  - addition                        => info
 *  - changed value                   => info, or review if the key name looks security-relevant
 * Arrays are compared as unordered collections.
 */
export function diffGeneric(
  before: JsonValue | undefined,
  after: JsonValue | undefined,
  path: string,
  out: Finding[],
): void {
  if (before === undefined && after === undefined) return;
  if (canonical(before) === canonical(after)) return;

  if (before === undefined) {
    out.push({
      code: "field-added",
      level: "info",
      path,
      message: `${path} was added: ${show(after)}.`,
      after: preview(after),
    });
    return;
  }
  if (after === undefined) {
    out.push({
      code: "field-removed",
      level: "review",
      path,
      message: `${path} was removed (was ${show(before)}).`,
      why: "This field existed before and is absent now. If the edit was meant to touch something else, the value may have been dropped by accident.",
      before: preview(before),
    });
    return;
  }

  if (isObject(before) && isObject(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const k of keys) {
      diffGeneric(
        hasOwn(before, k) ? getOwn(before, k) : undefined,
        hasOwn(after, k) ? getOwn(after, k) : undefined,
        path === "" ? k : `${path}.${k}`,
        out,
      );
    }
    return;
  }

  if (Array.isArray(before) && Array.isArray(after)) {
    const score = (b: JsonValue, a: JsonValue): number => {
      if (isObject(b) && isObject(a)) {
        let s = 0;
        for (const k of Object.keys(b)) {
          if (hasOwn(a, k) && canonical(getOwn(a, k)) === canonical(getOwn(b, k))) s++;
        }
        return s > 0 ? s : -1;
      }
      return -1;
    };
    const { pairs, restB, restA } = pairItems(before, after, canonical, canonical, score);
    for (const { bi, ai, exact } of pairs) {
      if (exact) continue;
      diffGeneric(before[bi], after[ai], `${path}[${bi}]`, out);
    }
    for (const bi of restB) {
      out.push({
        code: "list-item-removed",
        level: "review",
        path,
        message: `An item was removed from ${path}: ${show(before[bi])}.`,
        why: "A list entry present before is gone. Confirm it was removed on purpose.",
        before: preview(before[bi]),
      });
    }
    for (const ai of restA) {
      out.push({
        code: "list-item-added",
        level: "info",
        path,
        message: `An item was added to ${path}: ${show(after[ai])}.`,
        after: preview(after[ai]),
      });
    }
    return;
  }

  const sensitive = isSensitiveKey(path);
  out.push({
    code: "field-changed",
    level: sensitive ? "review" : "info",
    path,
    message: `${path} changed from ${show(before)} to ${show(after)}.`,
    ...(sensitive
      ? { why: "The field name suggests it influences severity, affected versions or fixes. Confirm the new value is intended." }
      : {}),
    before: preview(before),
    after: preview(after),
  });
}
