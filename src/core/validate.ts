import { Ajv2020 } from "ajv/dist/2020.js";
import type { ErrorObject, ValidateFunction } from "ajv/dist/2020.js";
import { parseCvss } from "./cvss.js";
import type { DuplicateKey } from "./load.js";
import { LATEST_KNOWN_SCHEMA_MINOR, SUPPORTED_SCHEMA_MAJOR, loadOsvSchema } from "./osvSchema.js";
import type { Finding, JsonObject, JsonValue, ValidationResult } from "./types.js";
import { asArray, asObjectArray, getOwn, isObject, isString, shorten } from "./util.js";

let compiled: ValidateFunction | undefined;

function getValidator(): ValidateFunction {
  if (!compiled) {
    // The schema is vendored upstream JSON, not authored here, so strict *schema* checks are
    // off. `format` stays annotation-only (as in JSON Schema 2020-12 by default); the checks
    // that matter for `format` (timestamps, URLs) are done explicitly below.
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
    compiled = ajv.compile(loadOsvSchema());
  }
  return compiled;
}

const EVENT_KINDS = ["introduced", "fixed", "last_affected", "limit"];
const GITHUB_SEVERITIES = ["LOW", "MODERATE", "HIGH", "CRITICAL"];
const GHSA_ID = /^GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}$/;
const SEMVER_LOOSE = /^v?[0-9]+([.][0-9]+){0,2}(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$/;
const CWE_ID = /^CWE-[1-9][0-9]*$/;
const RFC3339_Z = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})([.][0-9]+)?Z$/;

/** Convert an Ajv instancePath such as `/affected/0/package` to `affected[0].package`. */
export function pointerToPath(pointer: string): string {
  if (pointer === "") return "$";
  const segs = pointer
    .split("/")
    .slice(1)
    .map((s) => s.split("~1").join("/").split("~0").join("~"));
  let out = "";
  for (const s of segs) {
    if (/^[0-9]+$/.test(s)) out += `[${s}]`;
    else out += out === "" ? s : `.${s}`;
  }
  return out;
}

function instanceAt(data: JsonValue, pointer: string): JsonValue | undefined {
  let cur: JsonValue | undefined = data;
  if (pointer === "") return cur;
  for (const raw of pointer.split("/").slice(1)) {
    const seg = raw.split("~1").join("/").split("~0").join("~");
    if (Array.isArray(cur)) cur = cur[Number(seg)];
    else if (isObject(cur)) cur = getOwn(cur, seg);
    else return undefined;
  }
  return cur;
}

function describeBadEvent(ev: JsonValue | undefined): string {
  if (!isObject(ev)) return "Range event must be an object such as {\"introduced\": \"0\"}.";
  const keys = Object.keys(ev);
  const known = keys.filter((k) => EVENT_KINDS.includes(k));
  const unknown = keys.filter((k) => !EVENT_KINDS.includes(k));
  if (keys.length === 0) return "Range event is empty; expected one of: introduced, fixed, last_affected, limit.";
  if (known.length === 0) {
    return `Range event has no recognized key (${unknown.map((u) => `"${u}"`).join(", ")}); expected one of: introduced, fixed, last_affected, limit.`;
  }
  if (known.length > 1) {
    return `Range event must contain exactly one of introduced, fixed, last_affected, limit (found: ${known.join(", ")}).`;
  }
  const kind = known[0] as string;
  if (!isString(getOwn(ev, kind))) return `Range event "${kind}" must be a string.`;
  return `Range event is malformed (${keys.join(", ")}).`;
}

function ecosystemHint(value: JsonValue | undefined): string {
  if (!isString(value)) return "";
  const root = value.split(":")[0] ?? value;
  const known = knownEcosystems();
  const fix = known.find((k) => k.toLowerCase() === root.toLowerCase());
  return fix ? ` Did you mean "${fix}"? (names are case-sensitive)` : "";
}

let ecosystemCache: string[] | undefined;
function knownEcosystems(): string[] {
  if (!ecosystemCache) {
    const defs = getOwn(loadOsvSchema() as JsonObject, "$defs");
    const eco = isObject(defs) ? getOwn(defs, "ecosystemName") : undefined;
    ecosystemCache = isObject(eco) ? asArray(getOwn(eco, "enum")).filter(isString) : [];
  }
  return ecosystemCache;
}

/** Turn one raw Ajv error into a user-facing finding (or null for pure wrapper noise). */
function mapAjvError(err: ErrorObject, data: JsonObject): Finding | null {
  const sp = err.schemaPath;
  const path = pointerToPath(err.instancePath);
  const where = path === "$" ? "document" : path;
  const inst = instanceAt(data, err.instancePath);
  const err2 = (code: string, p: string, message: string): Finding => ({ code, level: "error", path: p, message });

  // Wrapper errors ("must match then schema") and oneOf-branch internals only add noise.
  if (err.keyword === "if") return null;
  if (sp.includes("/oneOf/") && err.keyword !== "oneOf") return null;

  if (err.keyword === "oneOf") {
    if (sp.includes("/allOf/1/")) {
      return err2(
        "invalid-git-commit",
        path,
        `GIT range event ${JSON.stringify(inst)} must use a full-length (40 or 64 hex digit, lower-case) commit hash, or "0".`,
      );
    }
    return err2("invalid-event", path, describeBadEvent(inst));
  }
  if (err.keyword === "contains" && sp.includes("/events/contains")) {
    return err2("range-missing-introduced", path, `Range has no "introduced" event; use {"introduced": "0"} to mean "from the first version".`);
  }
  if (err.keyword === "required" && sp.includes("/allOf/0/then") && !sp.includes("#/allOf/")) {
    return err2("git-range-missing-repo", `${path}.repo`, `GIT range requires a "repo" URL.`);
  }
  if (err.keyword === "not" && sp.includes("/allOf/2/then")) {
    return err2(
      "range-fixed-and-last-affected",
      path,
      `Range contains both "fixed" and "last_affected" events; the OSV schema forbids combining them.`,
    );
  }
  if (sp.includes("#/allOf/0/then")) {
    return err2(
      "severity-at-both-levels",
      path,
      "affected[].severity must be null/absent when the record has a top-level severity (the OSV schema allows only one level).",
    );
  }
  if (sp.includes("/then/properties/score/pattern")) {
    const parent = instanceAt(data, err.instancePath.split("/").slice(0, -1).join("/"));
    const type = isObject(parent) ? getOwn(parent, "type") : undefined;
    const score = inst;
    let detail = "does not match the vector syntax required for its type";
    if (isString(score) && isString(type)) {
      const expected = type === "CVSS_V2" ? "2" : type === "CVSS_V3" ? "3" : type === "CVSS_V4" ? "4" : undefined;
      const r = expected ? parseCvss(score, expected) : null;
      if (r && !r.ok) detail = r.error;
    }
    return { ...err2("invalid-cvss-vector", path, `${isString(type) ? type : "severity"} score is not a valid CVSS vector: ${detail}.`), after: isString(score) ? shorten(score) : null };
  }
  if (sp.includes("/then/properties/score/enum")) {
    return err2("invalid-value", path, `Ubuntu severity must be one of: negligible, low, medium, high, critical.`);
  }
  if (err.keyword === "additionalProperties") {
    const prop = String((err.params as { additionalProperty: string }).additionalProperty);
    return err2(
      "unknown-top-level-field",
      prop,
      `"${prop}" is not allowed at the top level of an OSV record (the schema sets additionalProperties: false). Put custom data under database_specific.`,
    );
  }
  if (err.keyword === "pattern") {
    if (sp.endsWith("ecosystemWithSuffix/pattern")) {
      return err2(
        "unknown-ecosystem",
        path,
        `Ecosystem ${JSON.stringify(inst)} is not one of the ecosystems listed in the OSV schema.${ecosystemHint(inst)}`,
      );
    }
    if (sp.endsWith("$defs/prefix/pattern")) {
      return err2(
        "invalid-id-prefix",
        path,
        `id ${JSON.stringify(isString(inst) ? shorten(inst, 40) : inst)} does not start with a database prefix registered in the OSV schema (for example GHSA-, CVE-, PYSEC-, or x_ for custom ids).`,
      );
    }
    if (sp.endsWith("$defs/timestamp/pattern")) {
      return err2("invalid-timestamp", path, `${where} must be an RFC 3339 UTC timestamp such as 2024-01-31T12:00:00Z.`);
    }
    return err2("invalid-value", path, `${where} does not match the required pattern.`);
  }
  switch (err.keyword) {
    case "required": {
      const missing = String((err.params as { missingProperty: string }).missingProperty);
      return err2(
        "missing-required-field",
        path === "$" ? missing : `${path}.${missing}`,
        `Required field "${missing}" is missing${where === "document" ? "" : ` from ${where}`}.`,
      );
    }
    case "type": {
      const t = (err.params as { type: string | string[] }).type;
      return err2("invalid-type", path, `${where} must be of type ${Array.isArray(t) ? t.join(" or ") : t}.`);
    }
    case "enum": {
      const allowed = (err.params as { allowedValues: unknown[] }).allowedValues;
      return err2("invalid-value", path, `${where} must be one of: ${allowed.map(String).join(", ")}.`);
    }
    case "minItems":
      return err2("empty-array", path, `${where} must contain at least one item.`);
    default:
      return err2("schema-violation", path, `${where} ${err.message ?? "is invalid"}.`);
  }
}

function parseVersion(v: string): { major: number; minor: number } | null {
  const m = /^([0-9]+)[.]([0-9]+)[.]([0-9]+)$/.exec(v);
  if (!m || m[1] === undefined || m[2] === undefined) return null;
  return { major: Number(m[1]), minor: Number(m[2]) };
}

function checkTimestamp(value: JsonValue | undefined, path: string, out: Finding[]): number | null {
  if (!isString(value)) return null;
  const m = RFC3339_Z.exec(value);
  if (!m) return null; // shape errors come from the schema layer
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const dt = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  const real =
    dt.getUTCFullYear() === y &&
    dt.getUTCMonth() === mo - 1 &&
    dt.getUTCDate() === d &&
    dt.getUTCHours() === h &&
    dt.getUTCMinutes() === mi &&
    s <= 59;
  if (!real) {
    out.push({
      code: "invalid-timestamp",
      level: "error",
      path,
      message: `${path} "${value}" is not a real calendar date/time.`,
    });
    return null;
  }
  return Date.parse(value);
}

/** Extra CVSS checks beyond the schema's regex: it accepts vectors that omit mandatory base metrics. */
function checkSeverityList(list: JsonValue | undefined, basePath: string, out: Finding[]): void {
  if (!Array.isArray(list)) return;
  const seen = new Map<string, number>();
  list.forEach((entry, idx) => {
    if (!isObject(entry)) return;
    const type = getOwn(entry, "type");
    const score = getOwn(entry, "score");
    const path = `${basePath}[${idx}]`;
    if (!isString(type) || !isString(score)) return;
    const expected = type === "CVSS_V2" ? "2" : type === "CVSS_V3" ? "3" : type === "CVSS_V4" ? "4" : null;
    if (expected) {
      const r = parseCvss(score, expected);
      if (!r.ok) {
        out.push({
          code: "invalid-cvss-vector",
          level: "error",
          path: `${path}.score`,
          message: `${type} score is not a valid CVSS vector: ${r.error}.`,
          after: shorten(score),
        });
      }
    }
    seen.set(type, (seen.get(type) ?? 0) + 1);
  });
  for (const [type, count] of seen) {
    if (count > 1) {
      out.push({
        code: "duplicate-severity-type",
        level: "warning",
        path: basePath,
        message: `${count} ${type} entries are present; consumers usually expect at most one per type.`,
      });
    }
  }
}

function checkAffected(affected: JsonValue | undefined, out: Finding[]): void {
  if (!Array.isArray(affected)) return;
  affected.forEach((entry, i) => {
    if (!isObject(entry)) return;
    const base = `affected[${i}]`;
    const pkg = getOwn(entry, "package");
    if (pkg === undefined) {
      const hasGit = asObjectArray(getOwn(entry, "ranges")).some((r) => getOwn(r, "type") === "GIT");
      if (!hasGit) {
        out.push({
          code: "affected-no-package",
          level: "warning",
          path: base,
          message: `${base} has no package, so it does not identify what is affected.`,
        });
      }
    }
    const ranges = getOwn(entry, "ranges");
    const versions = getOwn(entry, "versions");
    if ((!Array.isArray(ranges) || ranges.length === 0) && (!Array.isArray(versions) || versions.length === 0)) {
      out.push({
        code: "affected-no-versions",
        level: "warning",
        path: base,
        message: `${base} lists neither ranges nor versions, so no version is marked as affected.`,
      });
    }
    if (Array.isArray(ranges)) {
      ranges.forEach((range, j) => {
        if (isObject(range)) checkRange(range, `${base}.ranges[${j}]`, out);
      });
    }
    checkSeverityList(getOwn(entry, "severity"), `${base}.severity`, out);
  });
}

function checkRange(range: JsonObject, path: string, out: Finding[]): void {
  const type = getOwn(range, "type");
  const events = getOwn(range, "events");
  if (!Array.isArray(events)) return;
  events.forEach((ev, k) => {
    if (!isObject(ev)) return;
    for (const kind of EVENT_KINDS) {
      const value = getOwn(ev, kind);
      if (!isString(value)) continue;
      const evPath = `${path}.events[${k}].${kind}`;
      if (value.trim() === "") {
        out.push({ code: "empty-value", level: "warning", path: evPath, message: `Event "${kind}" is empty.` });
      } else if (type === "SEMVER" && value !== "0" && value !== "*" && !SEMVER_LOOSE.test(value)) {
        out.push({
          code: "non-semver-version",
          level: "warning",
          path: evPath,
          message: `"${shorten(value, 60)}" is not a valid semantic version, but the range type is SEMVER.`,
        });
      }
    }
  });
}

function checkReferences(references: JsonValue | undefined, out: Finding[]): void {
  if (!Array.isArray(references)) return;
  const seen = new Set<string>();
  references.forEach((ref, i) => {
    if (!isObject(ref)) return;
    const url = getOwn(ref, "url");
    if (!isString(url) || url === "") return;
    const path = `references[${i}].url`;
    let parsed: URL | null;
    try {
      parsed = new URL(url);
    } catch {
      parsed = null;
    }
    // The schema declares format "uri", which JSON Schema treats as an annotation; genuine
    // GitHub records occasionally contain scheme-less URLs, so these are warnings, not errors.
    if (!parsed) {
      out.push({ code: "invalid-url", level: "warning", path, message: `"${shorten(url, 80)}" is not an absolute URL.` });
      return;
    }
    if (parsed.protocol === "javascript:" || parsed.protocol === "data:") {
      out.push({
        code: "unsafe-url-scheme",
        level: "warning",
        path,
        message: `URL uses the "${parsed.protocol}" scheme, which does not belong in an advisory reference.`,
      });
    }
    if (seen.has(url)) {
      out.push({ code: "duplicate-reference", level: "warning", path, message: `Reference URL appears more than once: ${shorten(url, 80)}` });
    }
    seen.add(url);
  });
}

function checkStringList(list: JsonValue | undefined, path: string, id: string | null, out: Finding[]): void {
  if (!Array.isArray(list)) return;
  const seen = new Set<string>();
  for (const item of list) {
    if (!isString(item)) continue;
    if (seen.has(item)) {
      out.push({ code: "duplicate-entry", level: "warning", path, message: `${path} lists "${item}" more than once.` });
    }
    seen.add(item);
    if (id !== null && item === id && path === "aliases") {
      out.push({ code: "alias-is-id", level: "warning", path, message: `aliases contains the advisory's own id (${id}).` });
    }
  }
}

/** GitHub Advisory Database extensions live under database_specific (free-form in OSV). */
function checkGithubExtensions(data: JsonObject, out: Finding[]): void {
  const dbs = getOwn(data, "database_specific");
  if (!isObject(dbs)) return;
  const cwes = getOwn(dbs, "cwe_ids");
  if (cwes !== undefined && cwes !== null) {
    if (!Array.isArray(cwes)) {
      out.push({ code: "invalid-type", level: "error", path: "database_specific.cwe_ids", message: "database_specific.cwe_ids must be an array of CWE identifiers." });
    } else {
      const seen = new Set<string>();
      cwes.forEach((c, i) => {
        const path = `database_specific.cwe_ids[${i}]`;
        if (!isString(c) || !CWE_ID.test(c)) {
          out.push({
            code: "invalid-cwe-id",
            level: "error",
            path,
            message: `${isString(c) ? `"${shorten(c, 40)}"` : "Value"} is not a valid CWE id; expected the form "CWE-79".`,
          });
        } else if (seen.has(c)) {
          out.push({ code: "duplicate-entry", level: "warning", path, message: `${c} is listed more than once.` });
        } else seen.add(c);
      });
    }
  }
  const sev = getOwn(dbs, "severity");
  // GitHub emits null for records without a label; that is normal.
  if (sev !== undefined && sev !== null && (!isString(sev) || !GITHUB_SEVERITIES.includes(sev))) {
    out.push({
      code: "invalid-github-severity",
      level: "warning",
      path: "database_specific.severity",
      message: `database_specific.severity should be one of ${GITHUB_SEVERITIES.join(", ")} for GitHub advisories.`,
    });
  }
}

/** Validate a parsed advisory. Pure function: never mutates its input. */
export function validateAdvisory(data: JsonObject, duplicateKeys: DuplicateKey[] = []): ValidationResult {
  const findings: Finding[] = [];

  for (const d of duplicateKeys) {
    findings.push({
      code: "duplicate-key",
      level: "error",
      path: d.path,
      message: `Key "${d.key}" appears more than once in ${d.path}; JSON parsers silently keep only the last value, so data may be lost.`,
    });
  }

  let schemaVersion: string | null = null;
  const sv = getOwn(data, "schema_version");
  if (sv !== undefined) {
    if (!isString(sv)) {
      findings.push({ code: "invalid-type", level: "error", path: "schema_version", message: "schema_version must be a string such as \"1.6.0\"." });
    } else {
      schemaVersion = sv;
      const v = parseVersion(sv);
      if (!v) {
        findings.push({ code: "invalid-schema-version", level: "error", path: "schema_version", message: `schema_version "${shorten(sv, 40)}" is not a semantic version (expected e.g. "1.6.0").` });
      } else if (v.major !== SUPPORTED_SCHEMA_MAJOR) {
        findings.push({
          code: "unsupported-schema-version",
          level: "error",
          path: "schema_version",
          message: `OSV schema_version ${sv} is not supported; AdvisoryGuard validates OSV ${SUPPORTED_SCHEMA_MAJOR}.x only.`,
        });
      } else if (v.minor > LATEST_KNOWN_SCHEMA_MINOR) {
        findings.push({
          code: "newer-schema-version",
          level: "warning",
          path: "schema_version",
          message: `schema_version ${sv} is newer than the bundled OSV schema (${SUPPORTED_SCHEMA_MAJOR}.${LATEST_KNOWN_SCHEMA_MINOR}.x); it was validated against the bundled schema.`,
        });
      }
    }
  }

  const validate = getValidator();
  if (!validate(data)) {
    const mapped: Finding[] = [];
    const seenKeys = new Set<string>();
    for (const err of validate.errors ?? []) {
      const f = mapAjvError(err, data);
      if (!f) continue;
      const key = `${f.code}|${f.path}`;
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);
      mapped.push(f);
    }
    if (!mapped.some((f) => f.level === "error")) {
      // Never report "valid" when the schema said otherwise.
      const first = (validate.errors ?? [])[0];
      mapped.push({
        code: "schema-violation",
        level: "error",
        path: first ? pointerToPath(first.instancePath) : "$",
        message: `The record does not conform to the OSV schema${first?.message ? `: ${first.message}` : ""}.`,
      });
    }
    findings.push(...mapped);
  }

  // GitHub's REST/GraphQL advisory objects are a different format from OSV; say so plainly.
  if (getOwn(data, "id") === undefined && ["ghsa_id", "cve_id", "html_url"].some((k) => getOwn(data, k) !== undefined)) {
    findings.push({
      code: "not-osv-format",
      level: "error",
      path: "$",
      message:
        "This looks like GitHub's REST/GraphQL advisory format, not OSV JSON. AdvisoryGuard needs the OSV record: the file under advisories/ in github/advisory-database, or https://api.osv.dev/v1/vulns/<GHSA-ID>.",
    });
  }

  // Additional checks (not expressed by the schema, or giving better diagnostics).
  const id = isString(getOwn(data, "id")) ? (getOwn(data, "id") as string) : null;
  if (id !== null && id.toUpperCase().startsWith("GHSA-") && !GHSA_ID.test(id)) {
    findings.push({ code: "invalid-ghsa-id", level: "warning", path: "id", message: `"${shorten(id, 40)}" does not look like a valid GHSA id (GHSA-xxxx-xxxx-xxxx).` });
  }

  checkTimestamp(getOwn(data, "modified"), "modified", findings);
  const published = checkTimestamp(getOwn(data, "published"), "published", findings);
  const withdrawn = checkTimestamp(getOwn(data, "withdrawn"), "withdrawn", findings);
  if (withdrawn !== null && published !== null && withdrawn < published) {
    findings.push({ code: "withdrawn-before-published", level: "warning", path: "withdrawn", message: "withdrawn is earlier than published." });
  }

  checkStringList(getOwn(data, "aliases"), "aliases", id, findings);
  checkStringList(getOwn(data, "related"), "related", id, findings);
  checkStringList(getOwn(data, "upstream"), "upstream", id, findings);
  checkSeverityList(getOwn(data, "severity"), "severity", findings);
  checkAffected(getOwn(data, "affected"), findings);
  checkReferences(getOwn(data, "references"), findings);
  checkGithubExtensions(data, findings);

  // Completeness hints (warnings only; many valid records legitimately omit these).
  const hasTopSeverity = asArray(getOwn(data, "severity")).length > 0;
  const hasAffectedSeverity = asObjectArray(getOwn(data, "affected")).some((a) => asArray(getOwn(a, "severity")).length > 0);
  if (!hasTopSeverity && !hasAffectedSeverity) {
    findings.push({
      code: "no-severity",
      level: "warning",
      path: "severity",
      message: "No CVSS severity is present. If this advisory previously had one, make sure it was not dropped by an edit.",
    });
  }
  if (withdrawn === null && !Array.isArray(getOwn(data, "affected"))) {
    findings.push({ code: "no-affected", level: "warning", path: "affected", message: "No affected packages are listed." });
  }
  if (!Array.isArray(getOwn(data, "references")) || asArray(getOwn(data, "references")).length === 0) {
    findings.push({ code: "no-references", level: "warning", path: "references", message: "No references are listed." });
  }

  // Same problem reported by both the schema layer and an extra check: keep the first.
  const dedup: Finding[] = [];
  const keys = new Set<string>();
  for (const f of findings) {
    const k = `${f.code}|${f.path}`;
    if (keys.has(k)) continue;
    keys.add(k);
    dedup.push(f);
  }
  return { valid: !dedup.some((f) => f.level === "error"), schemaVersion, findings: dedup };
}
