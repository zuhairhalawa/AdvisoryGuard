import type { JsonObject, JsonValue } from "./types.js";

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function isString(v: unknown): v is string {
  return typeof v === "string";
}

export function asArray(v: unknown): JsonValue[] {
  return Array.isArray(v) ? (v as JsonValue[]) : [];
}

export function asObjectArray(v: unknown): JsonObject[] {
  return asArray(v).filter(isObject);
}

export function hasOwn(o: object, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

export function getOwn(o: JsonObject, k: string): JsonValue | undefined {
  return hasOwn(o, k) ? o[k] : undefined;
}

/**
 * Canonical, deterministic string for a JSON value. Object keys are sorted and
 * arrays are treated as UNORDERED (their members are sorted), because ordering of
 * array members carries no meaning in advisory records.
 */
export function canonical(v: JsonValue | undefined): string {
  if (v === undefined) return "undefined";
  if (Array.isArray(v)) {
    return "[" + v.map((x) => canonical(x)).sort().join(",") + "]";
  }
  if (isObject(v)) {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

/** Deep clone of plain JSON data (own enumerable properties only). */
export function clone<T extends JsonValue>(v: T): T {
  if (Array.isArray(v)) return v.map((x) => clone(x)) as T;
  if (isObject(v)) {
    const out: JsonObject = {};
    for (const k of Object.keys(v)) {
      Object.defineProperty(out, k, {
        value: clone(v[k] as JsonValue),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out as T;
  }
  return v;
}

/** Truncate long strings for display. */
export function shorten(s: string, max = 120): string {
  return s.length > max ? s.slice(0, max - 3) + "..." : s;
}

export function plural(n: number, singular: string, pluralForm = singular + "s"): string {
  return `${n} ${n === 1 ? singular : pluralForm}`;
}

const BACKSLASH = String.fromCharCode(92);

/** Escape terminal control characters in untrusted text before printing. */
export function sanitizeForTerminal(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f?-??-?]/g, (c) =>
    BACKSLASH + "u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
