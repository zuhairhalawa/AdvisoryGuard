import type { DiffResult, Finding, Level, ValidationResult } from "../core/types.js";
import { plural, sanitizeForTerminal } from "../core/util.js";
import type { Style } from "./style.js";

const LABEL: Record<Level, string> = {
  error: "ERROR  ",
  review: "REVIEW ",
  warning: "WARNING",
  info: "INFO   ",
};

function paint(style: Style, level: Level, s: string): string {
  switch (level) {
    case "error":
      return style.red(style.bold(s));
    case "review":
      return style.yellow(style.bold(s));
    case "warning":
      return style.yellow(s);
    default:
      return style.cyan(s);
  }
}

function indent(text: string, pad: string): string {
  return text
    .split("\n")
    .map((l) => pad + l)
    .join("\n");
}

function renderFinding(f: Finding, style: Style): string {
  const tag = f.acknowledged ? "ALLOWED" : LABEL[f.level];
  const head = `${paint(style, f.acknowledged ? "info" : f.level, tag)} ${style.bold(f.code)}  ${style.dim(sanitizeForTerminal(f.path))}`;
  const lines = [head, indent(sanitizeForTerminal(f.message), "  ")];
  if (f.why && !f.acknowledged) lines.push(indent(`${style.dim("Why:")} ${sanitizeForTerminal(f.why)}`, "  "));
  return lines.join("\n");
}

export function renderValidate(file: string, result: ValidationResult, style: Style): string {
  const out: string[] = [];
  out.push(style.bold(`AdvisoryGuard validate  ${sanitizeForTerminal(file)}`));
  if (result.schemaVersion) out.push(style.dim(`OSV schema_version: ${sanitizeForTerminal(result.schemaVersion)}`));
  out.push("");
  for (const f of result.findings) out.push(renderFinding(f, style), "");
  const errors = result.findings.filter((f) => f.level === "error").length;
  const warnings = result.findings.filter((f) => f.level === "warning").length;
  if (result.valid) {
    out.push(
      style.green(style.bold("VALID")) +
        (warnings > 0 ? ` with ${plural(warnings, "warning")}.` : ": no problems found."),
    );
  } else {
    out.push(
      style.red(style.bold("INVALID")) +
        `: ${plural(errors, "error")}${warnings > 0 ? `, ${plural(warnings, "warning")}` : ""}.`,
    );
  }
  return out.join("\n");
}

export function renderDiff(beforeFile: string, afterFile: string, result: DiffResult, style: Style): string {
  const out: string[] = [];
  out.push(style.bold("AdvisoryGuard diff"));
  out.push(`  before: ${sanitizeForTerminal(beforeFile)}`);
  out.push(`  after:  ${sanitizeForTerminal(afterFile)}`);
  if (result.advisoryId) out.push(`  id:     ${sanitizeForTerminal(result.advisoryId)}`);
  out.push("");

  const afterIssues = result.after.findings.filter((f) => f.level === "error" || f.level === "warning");
  if (afterIssues.length > 0) {
    out.push(style.bold(`Validation of ${sanitizeForTerminal(afterFile)}`), "");
    for (const f of afterIssues) out.push(renderFinding(f, style), "");
  }
  const beforeErrors = result.before.findings.filter((f) => f.level === "error");
  if (beforeErrors.length > 0) {
    out.push(
      style.dim(
        `Note: ${sanitizeForTerminal(beforeFile)} itself has ${plural(beforeErrors.length, "validation error")} ` +
          `(run "advisoryguard validate" on it for details). Comparison was still performed where possible.`,
      ),
      "",
    );
  }

  if (result.findings.length === 0 && result.identical) {
    out.push("No differences: the advisories are semantically identical (formatting and ordering are ignored).", "");
  } else if (result.findings.length === 0 && result.before.valid && result.after.valid) {
    out.push("No meaningful differences.", "");
  } else {
    if (result.findings.length > 0) out.push(style.bold("Changes"), "");
    for (const f of result.findings) out.push(renderFinding(f, style), "");
  }

  const c = result.counts;
  const parts: string[] = [];
  if (c.review > 0) parts.push(`${plural(c.review, "change")} need${c.review === 1 ? "s" : ""} review`);
  if (c.info > 0) parts.push(`${c.info} informational`);
  if (result.acknowledged > 0) parts.push(`${result.acknowledged} acknowledged via --allow`);
  const detail = parts.length > 0 ? ` (${parts.join(", ")})` : "";
  if (result.status === "invalid") {
    out.push(style.red(style.bold("INVALID")) + `: the edited advisory is not valid OSV data${detail}.`);
  } else if (result.status === "review") {
    out.push(style.yellow(style.bold("REVIEW REQUIRED")) + detail);
  } else {
    out.push(style.green(style.bold("OK")) + `: no changes require review${detail}.`);
  }
  return out.join("\n");
}
