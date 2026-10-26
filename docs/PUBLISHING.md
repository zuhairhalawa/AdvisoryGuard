# Publishing checklist for v0.1.0 (maintainer only)

Legend: **[x]** done and verified, **[ ]** pending or not verified.

## Status summary

- [x] Repository created and pushed (`zuhairhalawa/AdvisoryGuard`).
- [x] First CI run passed on Ubuntu, macOS and Windows.
- [x] Git tag `v0.1.0` exists on `origin` (it points at commit `907b151`).
- [x] Published to npm as `advisoryguard@0.1.0` (public, `latest` dist-tag).
- [x] GitHub Release for `v0.1.0` is published (not a draft, not a pre-release): https://github.com/zuhairhalawa/AdvisoryGuard/releases/tag/v0.1.0
- [x] CI run #40367715585 completed with conclusion `success` (commit `907b151`).
- [x] Repository homepage is `https://www.npmjs.com/package/advisoryguard`.
- [x] Repository topics are set (see step 1).
- [x] Private vulnerability reporting is enabled (verified 2026-10-26 via the GitHub API: `enabled: true`).

## 1. Create and push the repository

Status: **done** (repository created, `main` pushed). Topics, homepage and Private vulnerability reporting were verified.

Repository name: `AdvisoryGuard` under `zuhairhalawa` (public, MIT).

Description (GitHub "About"):

> Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited.

Topics (as verified on GitHub): `security`, `osv`, `cvss`, `typescript`, `cli`,
`security-advisories`, `supply-chain-security`

Homepage (as verified on GitHub): https://www.npmjs.com/package/advisoryguard

Commands used for the initial setup (kept for reference; do not re-run). The topic list in the last
command is the original plan; the topics actually set on the repository are the ones listed above:

```sh
git init -b main
git add .
git status            # confirm no node_modules/, dist/, .tmp/ or *.tgz are staged
git commit -m "AdvisoryGuard v0.1.0"
gh repo create zuhairhalawa/AdvisoryGuard --public --source . --description "Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited." --push
gh repo edit zuhairhalawa/AdvisoryGuard --add-topic osv --add-topic ghsa --add-topic github-advisory-database --add-topic security-advisories --add-topic cvss --add-topic vulnerability --add-topic supply-chain-security --add-topic json-schema --add-topic cli --add-topic nodejs --add-topic typescript
```

Confirmed:

- [x] Topics and homepage are set on the repository (the description is also set).
- [x] **Security > Private vulnerability reporting** is enabled (SECURITY.md refers to it). Enabled 2026-10-26 with `gh api -X PUT repos/zuhairhalawa/AdvisoryGuard/private-vulnerability-reporting`; verified with `gh api repos/zuhairhalawa/AdvisoryGuard/private-vulnerability-reporting` returning `{"enabled":true}`.

## 2. Wait for CI

Status: **done**. The first run of `.github/workflows/ci.yml` (Ubuntu/macOS/Windows x Node 22/24,
packed-tarball runtime check on Node 20, `npm audit`, vendored-schema verification) passed, including
the Linux and macOS runners that had not been exercised before.

## 3. Tag and release

Status: **done** (tag exists; GitHub Release is published).

- [x] Tag `v0.1.0` exists on `origin`.
- [x] GitHub Release `v0.1.0` ("AdvisoryGuard v0.1.0") is published, not a draft or pre-release.

Do not move or re-create the tag or the Release.

## 4. Publish to npm (needs your npm login / 2FA)

Status: **done.** `advisoryguard@0.1.0` is publicly available on npm and is the `latest` dist-tag.
Do not publish `0.1.0` again; any further change needs a new version.

- [x] `npm view advisoryguard@0.1.0 version` returns `0.1.0`.
- [x] README "Status" note updated to say the package is available on npm.

Optional smoke test from a clean directory:

```sh
npx advisoryguard@0.1.0 --version
```
