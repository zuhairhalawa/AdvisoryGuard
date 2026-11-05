import { createHash } from "node:crypto";
import { PAIRING_LIMIT_WHY, pairItems } from "../pairing.js";
import type { Finding, JsonObject, JsonValue } from "../types.js";
import { asObjectArray, canonical, getOwn, hasOwn, isObject, isString, shorten } from "../util.js";

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
    const { pairs, restB, restA, skipped } = pairItems(before, after, canonical, canonical, score);
    // Only objects can pair, so a list without them on both sides did not lose anything to the limit.
    if (skipped && restB.some((i) => isObject(before[i])) && restA.some((i) => isObject(after[i]))) {
      out.push({
        code: "pairing-limit",
        level: "review",
        path,
        message: `Too many items in ${path} to match them up; changed items may be reported as removed and added.`,
        why: PAIRING_LIMIT_WHY,
      });
    }
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

/** An identity short enough to repeat in every path and message, which stays distinct from other long ones. */
function pathLabel(id: string): string {
  if (id.length <= 120) return id;
  return `${shorten(id, 100)} #${createHash("sha256").update(id).digest("hex").slice(0, 12)}`;
}

/** A group key that no real identity can equal, because an identity can be any string, including an empty one. */
const NO_IDENTITY = Symbol("no identity");

/**
 * For comparers that read only some keys of each list item: compares everything else in the items both
 * sides have, so that removing a key still needs review. `identity` says which items are the same; an
 * item only one side has is left to the comparer, which reports it. Items with no identity are compared
 * as a group, so that nothing is dropped.
 */
export function diffOtherKeys(
  before: JsonValue | undefined,
  after: JsonValue | undefined,
  known: readonly string[],
  identity: (item: JsonObject) => string | undefined,
  path: string,
  out: Finding[],
): void {
  const group = (v: JsonValue | undefined): Map<string | symbol, JsonObject[]> => {
    const groups = new Map<string | symbol, JsonObject[]>();
    for (const item of asObjectArray(v)) {
      const id = identity(item) ?? NO_IDENTITY;
      // A known key holding anything but a string is invisible to the comparer, so it counts as other.
      const rest = Object.fromEntries(Object.entries(item).filter(([k, value]) => !(known.includes(k) && isString(value)))) as JsonObject;
      const list = groups.get(id);
      if (list) list.push(rest);
      else groups.set(id, [rest]);
    }
    return groups;
  };
  const inBefore = group(before);
  const inAfter = group(after);
  const ids = [...new Set([...inBefore.keys(), ...inAfter.keys()])].filter((id) => typeof id === "string").sort();
  for (const id of [...ids, NO_IDENTITY]) {
    const xs = inBefore.get(id);
    const ys = inAfter.get(id);
    if (id !== NO_IDENTITY && (!xs || !ys)) continue;
    const where = typeof id === "string" ? `${path}[${pathLabel(id)}]` : path;
    const [x] = xs ?? [];
    const [y] = ys ?? [];
    if (x && y && xs?.length === 1 && ys?.length === 1) {
      diffGeneric(x, y, where, out);
    } else {
      const nonEmpty = (list: JsonObject[] | undefined): JsonObject[] => (list ?? []).filter((o) => Object.keys(o).length > 0);
      diffGeneric(nonEmpty(xs), nonEmpty(ys), where, out);
    }
  }
}
