export { diffFiles, diffTexts, validateFile, validateText } from "./core/analyze.js";
export type { AnalyzeOptions } from "./core/analyze.js";
export { diffAdvisories } from "./core/diff/index.js";
export { validateAdvisory } from "./core/validate.js";
export { parseAdvisoryText, readAdvisoryFile, AdvisoryIoError } from "./core/load.js";
export { parseCvss, cvss3BaseScore } from "./core/cvss.js";
export type {
  DiffResult,
  DiffStatus,
  Finding,
  JsonObject,
  JsonValue,
  Level,
  ValidationResult,
} from "./core/types.js";
export { VERSION } from "./version.js";
