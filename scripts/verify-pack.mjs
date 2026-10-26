import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Verifies the DISTRIBUTED package: pack, inspect tarball, install into a fresh temporary
// project, run the installed CLI against fixtures. Never publishes anything.
//   node scripts/verify-pack.mjs                      pack the repo, then verify everything
//   node scripts/verify-pack.mjs --tarball x.tgz      verify an existing tarball only (runtime
//                                                     compatibility on any Node version; no dev tools needed)
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const isWin = process.platform === "win32";
const npm = isWin ? "npm.cmd" : "npm";
const BACKSLASH = String.fromCharCode(92);
const tarballFlag = process.argv.indexOf("--tarball");
const givenTarball = tarballFlag >= 0 ? resolve(process.argv[tarballFlag + 1] ?? "") : null;
const results = [];
let failed = false;

function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  if (!ok) failed = true;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  - " + detail : ""}`);
}

function sh(cmd, args, opts = {}) {
  if (isWin && cmd.endsWith(".cmd")) {
    // .cmd files need a shell on Windows; pass one pre-quoted command line (no args array).
    const line = [cmd, ...args].map((a) => (a.includes(" ") ? `"${a}"` : a)).join(" ");
    return spawnSync(line, { encoding: "utf8", shell: true, ...opts });
  }
  return spawnSync(cmd, args, { encoding: "utf8", ...opts });
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
console.log(`node ${process.version} on ${process.platform}/${process.arch}, npm ${sh(npm, ["--version"]).stdout.trim()}`);
const work = mkdtempSync(join(tmpdir(), "advisoryguard-pack-"));
try {
  let tarball = givenTarball;
  if (!tarball) {
    // 1. pack the repository
    const packDir = join(work, "pack");
    mkdirSync(packDir);
    const pack = sh(npm, ["pack", "--json", "--pack-destination", packDir], { cwd: root });
    check("npm pack succeeds", pack.status === 0, pack.status === 0 ? "" : pack.stderr);
    if (pack.status !== 0) throw new Error("pack failed");
    const info = JSON.parse(pack.stdout)[0];
    tarball = join(packDir, info.filename);
    const files = info.files.map((f) => f.path.split(BACKSLASH).join("/"));
    console.log(`      tarball: ${info.filename} (${info.size} bytes, ${files.length} files, unpacked ${info.unpackedSize})`);

    // 2. tarball contents
    const required = [
      "package.json", "LICENSE", "README.md", "CHANGELOG.md", "THIRD_PARTY_NOTICES.md",
      "dist/cli/bin.js", "dist/index.js", "dist/index.d.ts",
      "vendor/osv-schema/schema.json", "vendor/osv-schema/LICENSE", "vendor/osv-schema/PROVENANCE.json",
    ];
    for (const f of required) check(`tarball contains ${f}`, files.includes(f));
    const badPrefixes = ["src/", "test/", "scripts/", "node_modules/", ".github/", ".tmp/"];
    const forbidden = files.filter((f) => badPrefixes.some((p) => f.startsWith(p)) || (f.endsWith(".ts") && !f.endsWith(".d.ts")));
    check("tarball contains no sources, tests, scripts or CI files", forbidden.length === 0, forbidden.join(", "));
    const secretNames = [".env", ".npmrc", "id_rsa"];
    const secrets = files.filter((f) => secretNames.some((s) => f.endsWith(s)) || f.endsWith(".pem") || f.endsWith(".key"));
    check("tarball contains no secret-looking files", secrets.length === 0, secrets.join(", "));
    check("tarball contains no source maps or tsbuildinfo", !files.some((f) => f.endsWith(".map") || f.endsWith(".tsbuildinfo")));

    // 3. metadata
    check("license is MIT", pkg.license === "MIT");
    check("bin entry points at dist/cli/bin.js", pkg.bin?.advisoryguard === "dist/cli/bin.js");
    check("engines.node declared", typeof pkg.engines?.node === "string", pkg.engines?.node);
    check("repository, homepage and bugs declared", Boolean(pkg.repository?.url && pkg.homepage && pkg.bugs?.url));
    check("runtime dependency is only ajv", Object.keys(pkg.dependencies ?? {}).join(",") === "ajv");
    check("no install/postinstall scripts", !["preinstall", "install", "postinstall"].some((s) => pkg.scripts?.[s]));
    const binSrc = readFileSync(join(root, "dist", "cli", "bin.js"), "utf8");
    check("bin file starts with a node shebang", binSrc.startsWith("#!/usr/bin/env node"));
  } else {
    check("using provided tarball", existsSync(givenTarball), givenTarball);
  }

  // 4. fresh project install
  const proj = join(work, "fresh-project");
  mkdirSync(proj);
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "fresh", version: "1.0.0", private: true }));
  const install = sh(npm, ["install", tarball, "--no-audit", "--no-fund", "--loglevel=error"], { cwd: proj });
  check("npm install of tarball into fresh project", install.status === 0, install.status === 0 ? "" : install.stderr);
  if (install.status !== 0) throw new Error("install failed");
  const installedRoot = join(proj, "node_modules", "advisoryguard");
  check("installed package.json present", existsSync(join(installedRoot, "package.json")));
  check("installed LICENSE and third-party notices present", existsSync(join(installedRoot, "LICENSE")) && existsSync(join(installedRoot, "THIRD_PARTY_NOTICES.md")));
  const installedSchema = join(installedRoot, "vendor", "osv-schema", "schema.json");
  const prov = JSON.parse(readFileSync(join(installedRoot, "vendor", "osv-schema", "PROVENANCE.json"), "utf8"));
  const actualSha = createHash("sha256").update(readFileSync(installedSchema)).digest("hex");
  check("installed OSV schema matches its pinned upstream sha256", actualSha === prov.sha256, `${prov.tag} ${actualSha.slice(0, 12)}`);

  const fixtures = join(work, "fixtures");
  cpSync(join(root, "test", "fixtures"), fixtures, { recursive: true });
  writeFileSync(join(fixtures, "broken.json"), '{"id": "X", "modified": }');

  // 5. run the installed CLI (both the .bin shim and the entry file), with networking BLOCKED
  const block = join(root, "scripts", "block-network.cjs");
  const shim = join(proj, "node_modules", ".bin", isWin ? "advisoryguard.cmd" : "advisoryguard");
  check(".bin shim created by npm", existsSync(shim));
  // NODE_OPTIONS treats backslashes as escapes, so always hand it a forward-slash path.
  const nodeOpts = `--require "${block.split(BACKSLASH).join("/")}"`;
  const env = { ...process.env, NO_COLOR: "1", NODE_OPTIONS: nodeOpts };
  const quote = (a) => `"${a}"`;
  const runShim = (args) =>
    isWin
      ? spawnSync([quote(shim), ...args.map(quote)].join(" "), { cwd: proj, env, shell: true, encoding: "utf8" })
      : spawnSync(shim, args, { cwd: proj, env, encoding: "utf8" });
  const entry = join(installedRoot, "dist", "cli", "bin.js");
  const runEntry = (args) => spawnSync(process.execPath, [entry, ...args], { cwd: proj, encoding: "utf8", env });

  const ver = runShim(["--version"]);
  check("installed shim: --version matches package.json", ver.status === 0 && ver.stdout.trim() === pkg.version, ver.stdout.trim());

  const before = join(fixtures, "regression-before.json");
  const bug = join(fixtures, "regression-after-bug.json");
  const good = join(fixtures, "regression-after-correct.json");
  const realDir = join(fixtures, "real");
  const real = join(realDir, "GHSA-6hwc-9h8r-3vmf.json");
  const cases = [
    ["validate valid fixture => 0", ["validate", before], 0, "VALID"],
    ["validate genuine GitHub advisory (CVSS v3+v4) => 0", ["validate", real], 0, "VALID"],
    ["validate malformed JSON => 2", ["validate", join(fixtures, "broken.json")], 2, "Invalid JSON"],
    ["diff identical => 0", ["diff", before, before], 0, "semantically identical"],
    ["diff CVSS-deletion regression => 1", ["diff", before, bug], 1, "severity-removed"],
    ["diff correct package fix => 1 (rename review only)", ["diff", before, good], 1, "package-renamed"],
    ["diff missing file => 3", ["diff", before, join(fixtures, "nope.json")], 3, null],
  ];
  for (const [name, args, code, needle] of cases) {
    for (const [label, runner] of [["shim", runShim], ["entry", runEntry]]) {
      const r = runner(args);
      const text = r.stdout + r.stderr;
      check(`installed ${label} (network blocked): ${name}`, r.status === code && (needle === null || text.includes(needle)) && !text.includes("NETWORK-ATTEMPT-BLOCKED"), `exit ${r.status}`);
    }
  }

  const j = runEntry(["diff", before, bug, "--json"]);
  let parsed = null;
  try {
    parsed = JSON.parse(j.stdout);
  } catch {
    parsed = null;
  }
  check(
    "installed: --json output parses and reports 2 removed severities",
    parsed?.findings?.filter((f) => f.code === "severity-removed").length === 2 && parsed?.exitCode === 1,
  );

  // the library entry point works from the installed package too
  const libCode = 'import("advisoryguard").then((m) => { process.stdout.write(typeof m.diffFiles + "," + typeof m.validateFile + "," + m.VERSION); })';
  const lib = spawnSync(process.execPath, ["--input-type=module", "-e", libCode], { cwd: proj, encoding: "utf8", env });
  check("installed: library import exposes diffFiles/validateFile/VERSION", lib.stdout === `function,function,${pkg.version}`, lib.stdout || lib.stderr);

  // the blocker itself works (so the checks above are meaningful)
  const probe = spawnSync(process.execPath, ["-e", 'fetch("http://127.0.0.1:9").catch(() => {})'], { env, encoding: "utf8" });
  check("network blocker self-test", probe.status === 99 && probe.stderr.includes("NETWORK-ATTEMPT-BLOCKED"));

  // 6. dependency audit of the installed (production) tree
  const audit = sh(npm, ["audit", "--omit=dev", "--json"], { cwd: proj });
  let auditJson = null;
  try {
    auditJson = JSON.parse(audit.stdout);
  } catch {
    auditJson = null;
  }
  if (auditJson?.metadata?.vulnerabilities) {
    const v = auditJson.metadata.vulnerabilities;
    check("npm audit (production deps of installed package)", v.total === 0, JSON.stringify(v));
  } else {
    console.log("SKIP  npm audit could not be evaluated (offline?)");
  }
} catch (e) {
  if (!failed) {
    failed = true;
    console.error(String(e));
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} package checks passed`);
process.exitCode = failed ? 1 : 0;
