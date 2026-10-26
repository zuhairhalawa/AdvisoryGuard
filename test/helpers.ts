import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { diffTexts } from "../src/core/analyze.js";
import type { DiffResult, Finding, JsonObject } from "../src/core/types.js";

export const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

export function fixturePath(name: string): string {
  return FIXTURES + name;
}

export function loadFixture(name: string): JsonObject {
  return JSON.parse(readFileSync(fixturePath(name), "utf8")) as JsonObject;
}

/** Fresh deep copy of the realistic base advisory (2 packages, 3 ranges, CVSS v3 + v4). */
export function base(): JsonObject {
  return loadFixture("regression-before.json");
}

/** Return a modified deep copy of the base advisory. */
export function edit(mutator: (doc: Record<string, any>) => void, from: JsonObject = base()): JsonObject {
  const copy = structuredClone(from) as Record<string, any>;
  mutator(copy);
  return copy as JsonObject;
}

export function diff(before: JsonObject, after: JsonObject, allow: string[] = []): DiffResult {
  return diffTexts(JSON.stringify(before), JSON.stringify(after), { allow });
}

export function codes(result: DiffResult, level?: Finding["level"]): string[] {
  return result.findings.filter((f) => (level ? f.level === level : true)).map((f) => f.code);
}

export function reviewCodes(result: DiffResult): string[] {
  return codes(result, "review");
}
