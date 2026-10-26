import { readFileSync } from "node:fs";

/** Package version, read from the package.json that ships next to `dist/`. */
export const VERSION: string = (() => {
  try {
    const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
})();
