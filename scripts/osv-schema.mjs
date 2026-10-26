import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Maintainer tool (network). Never used by the CLI at runtime.
//   node scripts/osv-schema.mjs verify          compare vendored files with upstream at the pinned commit
//   node scripts/osv-schema.mjs update <tag>    re-pin to an upstream release tag (then update src/core/osvSchema.ts)
const dir = fileURLToPath(new URL("../vendor/osv-schema/", import.meta.url));
const provPath = dir + "PROVENANCE.json";
const prov = JSON.parse(readFileSync(provPath, "utf8"));
const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const rawUrl = (commit, file) => `https://raw.githubusercontent.com/ossf/osv-schema/${commit}/${file}`;

async function fetchBytes(url) {
  const r = await fetch(url, { headers: { "User-Agent": "advisoryguard-maintainer" } });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}

const [cmd = "verify", tag] = process.argv.slice(2);

if (cmd === "verify") {
  const local = readFileSync(dir + "schema.json");
  const localLicense = readFileSync(dir + "LICENSE");
  const upstream = await fetchBytes(rawUrl(prov.commit, prov.path));
  const upstreamLicense = await fetchBytes(rawUrl(prov.commit, "LICENSE"));
  const checks = [
    ["vendored schema.json matches pinned sha256", sha(local) === prov.sha256],
    ["vendored schema.json is byte-identical to upstream at the pinned commit", Buffer.compare(local, upstream) === 0],
    ["vendored LICENSE is byte-identical to upstream at the pinned commit", Buffer.compare(localLicense, upstreamLicense) === 0],
  ];
  for (const [name, ok] of checks) console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  console.log(`pinned: ${prov.repository} ${prov.tag} @ ${prov.commit}`);
  process.exitCode = checks.every(([, ok]) => ok) ? 0 : 1;
} else if (cmd === "update" && tag) {
  const ref = await (await fetch(`https://api.github.com/repos/ossf/osv-schema/git/ref/tags/${tag}`, { headers: { "User-Agent": "advisoryguard-maintainer" } })).json();
  const commit = ref?.object?.sha;
  if (!commit || ref.object.type !== "commit") throw new Error(`Cannot resolve tag ${tag} to a commit (annotated tag? resolve it manually)`);
  const schema = await fetchBytes(rawUrl(commit, prov.path));
  const license = await fetchBytes(rawUrl(commit, "LICENSE"));
  writeFileSync(dir + "schema.json", schema);
  writeFileSync(dir + "LICENSE", license);
  const next = { ...prov, tag, commit, sha256: sha(schema), retrieved: new Date().toISOString().slice(0, 10) };
  writeFileSync(provPath, JSON.stringify(next, null, 2) + "\n");
  console.log(`Updated to ${tag} @ ${commit}\nsha256 ${next.sha256}\nNow update OSV_SCHEMA_SOURCE (and THIRD_PARTY_NOTICES.md) to match, then run the tests.`);
} else {
  console.error("usage: node scripts/osv-schema.mjs verify | update <tag>");
  process.exitCode = 3;
}
