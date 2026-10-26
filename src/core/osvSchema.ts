import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * The official OpenSSF OSV JSON schema, vendored UNMODIFIED from ossf/osv-schema
 * (Apache-2.0, see vendor/osv-schema/LICENSE and THIRD_PARTY_NOTICES.md).
 *
 * The file is pinned to an exact upstream commit and verified by SHA-256 every time it is
 * loaded, so a corrupted or edited copy is detected instead of silently used.
 * `npm run update:schema -- <tag>` re-fetches and re-pins (manual, network, maintainers only).
 */
export const OSV_SCHEMA_SOURCE = {
  repository: "https://github.com/ossf/osv-schema",
  path: "validation/schema.json",
  tag: "v1.9.2",
  commit: "c8a57bdc5b0bc54646e140cabbb7834bd0b5aec9",
  sha256: "15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653",
  license: "Apache-2.0",
} as const;

/** Highest schema_version minor (1.x) known to be covered by the vendored schema. */
export const LATEST_KNOWN_SCHEMA_MINOR = 9;
export const SUPPORTED_SCHEMA_MAJOR = 1;

/** Location of the vendored schema; identical relative layout from src/ and from dist/. */
export const OSV_SCHEMA_FILE = new URL("../../vendor/osv-schema/schema.json", import.meta.url);

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

let cached: Record<string, unknown> | undefined;

/** Load the vendored schema, verifying its pinned hash. Throws if the file was altered. */
export function loadOsvSchema(): Record<string, unknown> {
  if (cached) return cached;
  const bytes = readFileSync(OSV_SCHEMA_FILE);
  const actual = sha256Hex(bytes);
  if (actual !== OSV_SCHEMA_SOURCE.sha256) {
    throw new Error(
      `Bundled OSV schema failed its integrity check (expected sha256 ${OSV_SCHEMA_SOURCE.sha256}, got ${actual}). ` +
        "Reinstall advisoryguard.",
    );
  }
  cached = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
  return cached;
}
