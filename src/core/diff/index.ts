import type { Finding, JsonObject, JsonValue } from "../types.js";
import { clone, getOwn, isObject } from "../util.js";
import { diffAffected } from "./affected.js";
import {
  diffCwe,
  diffGithubSeverity,
  diffIdList,
  diffId,
  diffReferences,
  diffText,
  diffTimestamps,
} from "./fields.js";
import { diffGeneric } from "./generic.js";
import { diffSeverity } from "./severity.js";

/** Top-level keys that have a dedicated comparer and are excluded from the generic pass. */
const HANDLED_TOP_LEVEL = [
  "id",
  "modified",
  "published",
  "withdrawn",
  "severity",
  "affected",
  "references",
  "aliases",
  "related",
  "upstream",
  "summary",
  "details",
];

function genericRemainder(doc: JsonObject): JsonValue {
  const out: JsonObject = {};
  for (const [k, v] of Object.entries(clone(doc))) {
    if (HANDLED_TOP_LEVEL.includes(k)) continue;
    if (k === "database_specific" && isObject(v)) {
      const rest = Object.fromEntries(Object.entries(v).filter(([dk]) => dk !== "cwe_ids" && dk !== "severity"));
      if (Object.keys(rest).length > 0) Object.defineProperty(out, k, { value: rest, enumerable: true, writable: true, configurable: true });
      continue;
    }
    Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
  }
  return out;
}

/**
 * Semantically compare two parsed advisories. Pure and deterministic: the inputs are
 * never mutated, and key order / array order / whitespace never matter.
 */
export function diffAdvisories(before: JsonObject, after: JsonObject): Finding[] {
  const out: Finding[] = [];
  diffId(before, after, out);
  diffTimestamps(before, after, out);
  diffSeverity(getOwn(before, "severity"), getOwn(after, "severity"), "severity", "", out);
  diffAffected(getOwn(before, "affected"), getOwn(after, "affected"), out);
  diffReferences(getOwn(before, "references"), getOwn(after, "references"), out);
  diffIdList("aliases", before, after, out);
  diffIdList("related", before, after, out);
  diffIdList("upstream", before, after, out);
  diffCwe(before, after, out);
  diffGithubSeverity(before, after, out);
  diffText("summary", before, after, out);
  diffText("details", before, after, out);
  diffGeneric(genericRemainder(before), genericRemainder(after), "", out);
  return out;
}
