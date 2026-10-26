import { parseArgs } from "node:util";
import { diffFiles, validateFile } from "../core/analyze.js";
import { AdvisoryIoError } from "../core/load.js";
import { diffToJson, validateToJson } from "../report/json.js";
import { createStyle } from "../report/style.js";
import { renderDiff, renderValidate } from "../report/text.js";
import { VERSION } from "../version.js";

/** Process exit codes (stable, documented in the README). */
export const EXIT = {
  OK: 0,
  REVIEW: 1,
  INVALID: 2,
  USAGE: 3,
} as const;

export interface CliIo {
  stdout: { write(s: string): unknown; isTTY?: boolean };
  stderr: { write(s: string): unknown };
  env: Record<string, string | undefined>;
}

export const USAGE = `advisoryguard ${VERSION}
Detect accidental data loss and risky metadata changes in OSV / GitHub Security Advisory JSON.

Usage:
  advisoryguard validate <advisory.json> [options]
  advisoryguard diff <before.json> <after.json> [options]

Options:
  -f, --format <text|json>   Output format (default: text)
      --json                 Shortcut for --format json
      --allow <codes>        Comma-separated finding codes to acknowledge as intended
                             (e.g. package-renamed,severity-changed). Repeatable.
      --fail-on <review|invalid>
                             diff only. "review" (default) exits 1 when changes need
                             review; "invalid" only fails for invalid advisory data.
      --no-color             Disable colored output (also honors NO_COLOR)
  -h, --help                 Show this help
  -v, --version              Show version

Exit codes:
  0  valid / no changes requiring review
  1  changes that require review (diff)
  2  invalid advisory data (malformed JSON or OSV schema violations)
  3  usage error or unreadable input file

AdvisoryGuard is offline: it never makes network requests and never modifies input files.
`;

function usageError(io: CliIo, message: string, json: boolean): number {
  if (json) {
    io.stdout.write(
      JSON.stringify({ tool: "advisoryguard", toolVersion: VERSION, error: { kind: "usage", message }, exitCode: EXIT.USAGE }, null, 2) + "\n",
    );
  } else {
    io.stderr.write(`advisoryguard: ${message}\nRun "advisoryguard --help" for usage.\n`);
  }
  return EXIT.USAGE;
}

function useColor(io: CliIo, noColorFlag: boolean, json: boolean): boolean {
  if (json || noColorFlag) return false;
  if (io.env["NO_COLOR"] !== undefined && io.env["NO_COLOR"] !== "") return false;
  const force = io.env["FORCE_COLOR"];
  if (force !== undefined && force !== "" && force !== "0") return true;
  return io.stdout.isTTY === true;
}

export function run(argv: readonly string[], io: CliIo): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        format: { type: "string", short: "f" },
        json: { type: "boolean" },
        allow: { type: "string", multiple: true },
        "fail-on": { type: "string" },
        "no-color": { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (e) {
    const wantsJson = argv.includes("--json") || argv.some((a, i) => (a === "--format" || a === "-f") && argv[i + 1] === "json");
    return usageError(io, (e as Error).message, wantsJson);
  }

  const { values, positionals } = parsed;
  if (values.help) {
    io.stdout.write(USAGE);
    return EXIT.OK;
  }
  if (values.version) {
    io.stdout.write(`${VERSION}\n`);
    return EXIT.OK;
  }

  const format = values.json ? "json" : (values.format ?? "text");
  if (format !== "text" && format !== "json") {
    return usageError(io, `Unknown --format "${format}" (expected "text" or "json").`, false);
  }
  const json = format === "json";

  const failOn = values["fail-on"] ?? "review";
  if (failOn !== "review" && failOn !== "invalid") {
    return usageError(io, `Unknown --fail-on "${failOn}" (expected "review" or "invalid").`, json);
  }

  const allow = (values.allow ?? [])
    .flatMap((s) => s.split(","))
    .map((s) => s.trim())
    .filter((s) => s !== "");

  const [command, ...files] = positionals;
  if (command === undefined) {
    io.stderr.write(USAGE);
    return EXIT.USAGE;
  }
  const style = createStyle(useColor(io, values["no-color"] === true, json));

  try {
    if (command === "validate") {
      if (files.length !== 1 || files[0] === undefined) {
        return usageError(io, "validate expects exactly one file: advisoryguard validate <advisory.json>", json);
      }
      const file = files[0];
      const result = validateFile(file);
      const code = result.valid ? EXIT.OK : EXIT.INVALID;
      io.stdout.write((json ? validateToJson(file, result, code) : renderValidate(file, result, style)) + "\n");
      return code;
    }

    if (command === "diff") {
      if (files.length !== 2 || files[0] === undefined || files[1] === undefined) {
        return usageError(io, "diff expects exactly two files: advisoryguard diff <before.json> <after.json>", json);
      }
      const [beforeFile, afterFile] = [files[0], files[1]];
      const result = diffFiles(beforeFile, afterFile, { allow });
      const code =
        result.status === "invalid" ? EXIT.INVALID : result.status === "review" && failOn === "review" ? EXIT.REVIEW : EXIT.OK;
      io.stdout.write(
        (json ? diffToJson(beforeFile, afterFile, result, code) : renderDiff(beforeFile, afterFile, result, style)) + "\n",
      );
      return code;
    }
  } catch (e) {
    if (e instanceof AdvisoryIoError) return usageError(io, e.message, json);
    throw e;
  }

  return usageError(io, `Unknown command "${command}" (expected "validate" or "diff").`, json);
}
