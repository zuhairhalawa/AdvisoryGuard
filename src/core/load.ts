import { readFileSync, statSync } from "node:fs";
import type { Finding, JsonObject, JsonValue } from "./types.js";
import { isObject } from "./util.js";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_DEPTH = 256;
const BACKSLASH = String.fromCharCode(92);

/** Raised for problems reading the file itself (missing, unreadable, too large). */
export class AdvisoryIoError extends Error {
  readonly path: string;
  constructor(path: string, message: string) {
    super(message);
    this.name = "AdvisoryIoError";
    this.path = path;
  }
}

export interface DuplicateKey {
  /** Location of the object containing the duplicate, e.g. `$.affected[0]`. */
  path: string;
  key: string;
}

export type ParseResult =
  | { ok: true; data: JsonObject; duplicateKeys: DuplicateKey[] }
  | { ok: false; finding: Finding };

/** Read a file as UTF-8 text. Never writes. Throws {@link AdvisoryIoError}. */
export function readAdvisoryFile(path: string): string {
  let st;
  try {
    st = statSync(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new AdvisoryIoError(path, `File not found: ${path}`);
    throw new AdvisoryIoError(path, `Cannot access ${path}: ${(e as Error).message}`);
  }
  if (!st.isFile()) throw new AdvisoryIoError(path, `Not a regular file: ${path}`);
  if (st.size > MAX_FILE_BYTES) {
    throw new AdvisoryIoError(path, `File too large (${st.size} bytes, limit ${MAX_FILE_BYTES}): ${path}`);
  }
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    throw new AdvisoryIoError(path, `Cannot read ${path}: ${(e as Error).message}`);
  }
}

interface SyntaxProblem {
  offset: number;
  message: string;
}

const NUMBER_RE = /-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?/y;
const ESCAPES = new Set(['"', BACKSLASH, "/", "b", "f", "n", "r", "t"]);

/**
 * Locate the first JSON syntax error. Node's own messages differ between versions (and
 * recent ones carry no position at all), so we find the position ourselves to give users
 * a stable "line X, column Y". Only called after JSON.parse has already failed.
 */
function locateSyntaxError(text: string): SyntaxProblem | null {
  let i = 0;
  const n = text.length;
  const fail = (message: string, offset = i): SyntaxProblem => ({ offset, message });
  const show = (): string => (i >= n ? "end of input" : `character ${JSON.stringify(text.charAt(i))}`);
  const ws = (): void => {
    while (i < n && WS.has(text.charAt(i))) i++;
  };

  const string = (): SyntaxProblem | null => {
    i++; // opening quote
    while (i < n) {
      const c = text.charAt(i);
      if (c === '"') {
        i++;
        return null;
      }
      if (c.charCodeAt(0) < 0x20) return fail("unescaped control character inside a string");
      if (c === BACKSLASH) {
        const e = text.charAt(i + 1);
        if (e === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) return fail("invalid unicode escape in string");
          i += 6;
          continue;
        }
        if (!ESCAPES.has(e)) return fail("invalid escape sequence in string");
        i += 2;
        continue;
      }
      i++;
    }
    return fail("unterminated string", n);
  };

  const value = (depth: number): SyntaxProblem | null => {
    if (depth > 512) return fail("nesting is too deep");
    ws();
    const c = text.charAt(i);
    if (c === "{") {
      i++;
      ws();
      if (text.charAt(i) === "}") {
        i++;
        return null;
      }
      for (;;) {
        ws();
        if (text.charAt(i) !== '"') return fail(`expected a property name in double quotes but found ${show()}`);
        const s = string();
        if (s) return s;
        ws();
        if (text.charAt(i) !== ":") return fail(`expected ":" after property name but found ${show()}`);
        i++;
        const v = value(depth + 1);
        if (v) return v;
        ws();
        const d = text.charAt(i);
        if (d === ",") {
          i++;
          continue;
        }
        if (d === "}") {
          i++;
          return null;
        }
        return fail(`expected "," or "}" but found ${show()}`);
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text.charAt(i) === "]") {
        i++;
        return null;
      }
      for (;;) {
        const v = value(depth + 1);
        if (v) return v;
        ws();
        const d = text.charAt(i);
        if (d === ",") {
          i++;
          continue;
        }
        if (d === "]") {
          i++;
          return null;
        }
        return fail(`expected "," or "]" but found ${show()}`);
      }
    }
    if (c === '"') return string();
    for (const lit of ["true", "false", "null"]) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return null;
      }
    }
    NUMBER_RE.lastIndex = i;
    const m = NUMBER_RE.exec(text);
    if (m && m[0] !== "") {
      i += m[0].length;
      return null;
    }
    return fail(`expected a JSON value but found ${show()}`);
  };

  const top = value(0);
  if (top) return top;
  ws();
  if (i < n) return fail(`unexpected ${show()} after the end of the JSON value`);
  return null;
}

function describeJsonError(text: string, err: Error): string {
  const problem = locateSyntaxError(text);
  if (!problem) return err.message;
  const before = text.slice(0, problem.offset);
  const line = before.split("\n").length;
  const col = problem.offset - before.lastIndexOf("\n");
  return `${problem.message} (line ${line}, column ${col})`;
}

/** Parse advisory JSON text into an object, detecting duplicate keys. */
export function parseAdvisoryText(rawText: string): ParseResult {
  const text = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;
  if (text.trim() === "") {
    return {
      ok: false,
      finding: { code: "empty-file", level: "error", path: "$", message: "File is empty; expected a JSON object." },
    };
  }
  let data: JsonValue;
  try {
    data = JSON.parse(text) as JsonValue;
  } catch (e) {
    return {
      ok: false,
      finding: {
        code: "invalid-json",
        level: "error",
        path: "$",
        message: `Invalid JSON: ${describeJsonError(text, e as Error)}`,
      },
    };
  }
  if (!isObject(data)) {
    const kind = Array.isArray(data) ? "an array" : data === null ? "null" : `a ${typeof data}`;
    return {
      ok: false,
      finding: {
        code: "not-an-object",
        level: "error",
        path: "$",
        message: `Top-level JSON value is ${kind}; an OSV advisory must be a JSON object.`,
      },
    };
  }
  let duplicateKeys: DuplicateKey[];
  try {
    duplicateKeys = scanDuplicateKeys(text);
  } catch (e) {
    if (e instanceof DepthError) {
      return {
        ok: false,
        finding: {
          code: "too-deep",
          level: "error",
          path: "$",
          message: `JSON is nested deeper than ${MAX_DEPTH} levels, which is not plausible for an advisory.`,
        },
      };
    }
    throw e;
  }
  return { ok: true, data, duplicateKeys };
}

class DepthError extends Error {}

const WS = new Set([" ", "\n", "\r", "\t"]);
const LITERAL_END = new Set([",", "]", "}", " ", "\n", "\r", "\t"]);

/**
 * JSON.parse silently keeps only the LAST value of a duplicated key, which can hide
 * data loss in hand-edited files. Scan the (already syntactically valid) text and
 * report duplicates. Recursion is bounded by MAX_DEPTH.
 */
function scanDuplicateKeys(text: string): DuplicateKey[] {
  const found: DuplicateKey[] = [];
  let i = 0;
  const n = text.length;

  const skipWs = (): void => {
    while (i < n && WS.has(text.charAt(i))) i++;
  };

  const readString = (): string => {
    const start = i;
    i++; // opening quote
    while (i < n) {
      const c = text.charAt(i);
      if (c === BACKSLASH) i += 2;
      else if (c === '"') {
        i++;
        break;
      } else i++;
    }
    return JSON.parse(text.slice(start, i)) as string;
  };

  const value = (path: string, depth: number): void => {
    if (depth > MAX_DEPTH) throw new DepthError();
    skipWs();
    const c = text.charAt(i);
    if (c === "{") {
      i++;
      const seen = new Set<string>();
      skipWs();
      if (text.charAt(i) === "}") {
        i++;
        return;
      }
      for (;;) {
        skipWs();
        const key = readString();
        if (seen.has(key)) found.push({ path, key });
        seen.add(key);
        skipWs();
        i++; // colon
        value(`${path}.${key}`, depth + 1);
        skipWs();
        if (text.charAt(i++) === "}") return;
      }
    } else if (c === "[") {
      i++;
      skipWs();
      if (text.charAt(i) === "]") {
        i++;
        return;
      }
      let idx = 0;
      for (;;) {
        value(`${path}[${idx++}]`, depth + 1);
        skipWs();
        if (text.charAt(i++) === "]") return;
      }
    } else if (c === '"') {
      readString();
    } else {
      while (i < n && !LITERAL_END.has(text.charAt(i))) i++;
    }
  };

  value("$", 0);
  return found;
}
