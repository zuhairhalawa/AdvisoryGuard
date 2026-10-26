import type { DiffResult, ValidationResult } from "../core/types.js";
import { VERSION } from "../version.js";

/** Version of the JSON output contract (independent of the package version). */
export const OUTPUT_SCHEMA_VERSION = 1;

function countLevels(result: ValidationResult): { errors: number; warnings: number } {
  return {
    errors: result.findings.filter((f) => f.level === "error").length,
    warnings: result.findings.filter((f) => f.level === "warning").length,
  };
}

export function validateToJson(file: string, result: ValidationResult, exitCode: number): string {
  const payload = {
    tool: "advisoryguard",
    toolVersion: VERSION,
    outputSchemaVersion: OUTPUT_SCHEMA_VERSION,
    command: "validate",
    file,
    valid: result.valid,
    schemaVersion: result.schemaVersion,
    summary: countLevels(result),
    findings: result.findings,
    exitCode,
  };
  return JSON.stringify(payload, null, 2);
}

export function diffToJson(beforeFile: string, afterFile: string, result: DiffResult, exitCode: number): string {
  const payload = {
    tool: "advisoryguard",
    toolVersion: VERSION,
    outputSchemaVersion: OUTPUT_SCHEMA_VERSION,
    command: "diff",
    before: beforeFile,
    after: afterFile,
    advisoryId: result.advisoryId,
    status: result.status,
    identical: result.identical,
    summary: { ...result.counts, acknowledged: result.acknowledged },
    findings: result.findings,
    validation: {
      before: { valid: result.before.valid, schemaVersion: result.before.schemaVersion, findings: result.before.findings },
      after: { valid: result.after.valid, schemaVersion: result.after.schemaVersion, findings: result.after.findings },
    },
    exitCode,
  };
  return JSON.stringify(payload, null, 2);
}
