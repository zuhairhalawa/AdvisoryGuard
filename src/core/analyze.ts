import { diffAdvisories } from "./diff/index.js";
import { parseAdvisoryText, readAdvisoryFile } from "./load.js";
import type { ParseResult } from "./load.js";
import type { DiffResult, DiffStatus, Finding, Level, ValidationResult } from "./types.js";
import { canonical, getOwn, isString } from "./util.js";
import { validateAdvisory } from "./validate.js";

export interface AnalyzeOptions {
  /** Finding codes to acknowledge (suppress from the exit status). */
  allow?: readonly string[];
}

const LEVEL_ORDER: Record<Level, number> = { error: 0, review: 1, warning: 2, info: 3 };

function validationFromParse(parsed: ParseResult): ValidationResult {
  if (!parsed.ok) return { valid: false, schemaVersion: null, findings: [parsed.finding] };
  return validateAdvisory(parsed.data, parsed.duplicateKeys);
}

/** Validate advisory JSON text. */
export function validateText(text: string): ValidationResult {
  return validationFromParse(parseAdvisoryText(text));
}

/** Validate a file on disk. Throws AdvisoryIoError when the file cannot be read. */
export function validateFile(path: string): ValidationResult {
  return validateText(readAdvisoryFile(path));
}

function emptyCounts(): Record<Level, number> {
  return { error: 0, review: 0, warning: 0, info: 0 };
}

export function sortFindings(findings: Finding[]): Finding[] {
  // Stable sort: severity of finding first, then original (deterministic) order.
  return findings
    .map((f, i) => ({ f, i }))
    .sort((x, y) => LEVEL_ORDER[x.f.level] - LEVEL_ORDER[y.f.level] || x.i - y.i)
    .map((x) => x.f);
}

/** Compare two advisory texts. */
export function diffTexts(beforeText: string, afterText: string, options: AnalyzeOptions = {}): DiffResult {
  const pb = parseAdvisoryText(beforeText);
  const pa = parseAdvisoryText(afterText);
  const before = validationFromParse(pb);
  const after = validationFromParse(pa);

  let findings: Finding[] = [];
  let identical = false;
  if (pb.ok && pa.ok) {
    identical = canonical(pb.data) === canonical(pa.data);
    findings = diffAdvisories(pb.data, pa.data);
  }

  const allow = new Set(options.allow ?? []);
  findings = findings.map((f) => (f.level === "review" && allow.has(f.code) ? { ...f, acknowledged: true } : f));

  const active = (f: Finding): boolean => f.acknowledged !== true;
  const counts = emptyCounts();
  for (const f of findings.filter(active)) counts[f.level]++;
  // Problems that make the edited ("after") advisory invalid are part of the verdict.
  const afterErrors = after.findings.filter((f) => f.level === "error");
  const status: DiffStatus = afterErrors.length > 0 ? "invalid" : counts.review > 0 ? "review" : "clean";

  const idValue = pa.ok ? getOwn(pa.data, "id") : pb.ok ? getOwn(pb.data, "id") : undefined;
  return {
    status,
    identical,
    advisoryId: isString(idValue) ? idValue : null,
    findings: sortFindings(findings),
    before,
    after,
    counts,
    acknowledged: findings.filter((f) => f.acknowledged === true).length,
  };
}

/** Compare two advisory files. Throws AdvisoryIoError when a file cannot be read. */
export function diffFiles(beforePath: string, afterPath: string, options: AnalyzeOptions = {}): DiffResult {
  return diffTexts(readAdvisoryFile(beforePath), readAdvisoryFile(afterPath), options);
}
