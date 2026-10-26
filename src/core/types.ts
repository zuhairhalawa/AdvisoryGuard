/** Shared types for AdvisoryGuard. */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

/**
 * - `error`   : the advisory data is invalid (schema/semantic violation).
 * - `review`  : a change that may be legitimate but needs a human decision.
 * - `warning` : valid, but unusual or incomplete data worth a look.
 * - `info`    : harmless / expected change or note.
 */
export type Level = "error" | "review" | "warning" | "info";

export interface Finding {
  /** Stable machine-readable code, e.g. `severity-removed`. */
  code: string;
  level: Level;
  /** Human-readable location, e.g. `severity[CVSS_V3]` or `affected[0].package.name`. */
  path: string;
  message: string;
  /** Why this matters / what to check. Present for review-level findings. */
  why?: string;
  before?: JsonValue;
  after?: JsonValue;
  /** True when the finding was suppressed through `--allow`. */
  acknowledged?: boolean;
}

export interface ValidationResult {
  valid: boolean;
  /** Detected OSV schema_version of the document (declared or defaulted). */
  schemaVersion: string | null;
  findings: Finding[];
}

export type DiffStatus = "clean" | "review" | "invalid";

export interface DiffResult {
  status: DiffStatus;
  /** True when the two documents are semantically identical (formatting/order only). */
  identical: boolean;
  advisoryId: string | null;
  findings: Finding[];
  before: ValidationResult;
  after: ValidationResult;
  /** Number of findings per level, excluding acknowledged ones. */
  counts: Record<Level, number>;
  /** Number of review findings suppressed with `--allow`. */
  acknowledged: number;
}
