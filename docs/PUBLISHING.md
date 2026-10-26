# Publishing checklist for v0.1.0 (maintainer only)

Legend: **[x]** done and verified, **[ ]** pending or not verified.

## Status summary

- [x] Repository created and pushed (`zuhairhalawa/AdvisoryGuard`).
- [x] First CI run passed on Ubuntu, macOS and Windows.
- [x] Git tag `v0.1.0` exists on `origin` (it points at commit `907b151`).
- [x] Published to npm as `advisoryguard@0.1.0` (public, `latest` dist-tag).
- [ ] GitHub Release for `v0.1.0`: not verified. Check the Releases page; create it if it is missing (step 3).
- [ ] Repository settings (topics, Private vulnerability reporting): not verified (step 1).

## 1. Create and push the repository

Status: **done** (repository created, `main` pushed). The settings below were not re-checked.

Repository name: `AdvisoryGuard` under `zuhairhalawa` (public, MIT).

Description (GitHub "About"):

> Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited.

Topics: `osv`, `ghsa`, `github-advisory-database`, `security-advisories`, `cvss`, `vulnerability`,
`supply-chain-security`, `json-schema`, `cli`, `nodejs`, `typescript`

Commands used for the initial setup (kept for reference; do not re-run):

```sh
git init -b main
git add .
git status            # confirm no node_modules/, dist/, .tmp/ or *.tgz are staged
git commit -m "AdvisoryGuard v0.1.0"
gh repo create zuhairhalawa/AdvisoryGuard --public --source . --description "Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited." --push
gh repo edit zuhairhalawa/AdvisoryGuard --add-topic osv --add-topic ghsa --add-topic github-advisory-database --add-topic security-advisories --add-topic cvss --add-topic vulnerability --add-topic supply-chain-security --add-topic json-schema --add-topic cli --add-topic nodejs --add-topic typescript
```

Still to confirm:

- [ ] Topics and description are set on the repository.
- [ ] **Security > Private vulnerability reporting** is enabled (SECURITY.md refers to it).

## 2. Wait for CI

Status: **done**. The first run of `.github/workflows/ci.yml` (Ubuntu/macOS/Windows x Node 22/24,
packed-tarball runtime check on Node 20, `npm audit`, vendored-schema verification) passed, including
the Linux and macOS runners that had not been exercised before.

## 3. Tag and release

Status: **tag done, GitHub Release not verified.**

- [x] Tag `v0.1.0` exists on `origin`.
- [ ] GitHub Release `v0.1.0` is published with `docs/release-notes-v0.1.0.md` as its notes.

If the Release does not exist yet, create it from the existing tag (do not move or re-create the tag):

```sh
gh release create v0.1.0 --title "AdvisoryGuard v0.1.0" --notes-file docs/release-notes-v0.1.0.md
```

## 4. Publish to npm (needs your npm login / 2FA)

Status: **done.** `advisoryguard@0.1.0` is publicly available on npm and is the `latest` dist-tag.
Do not publish `0.1.0` again; any further change needs a new version.

- [x] `npm view advisoryguard@0.1.0 version` returns `0.1.0`.
- [x] README "Status" note updated to say the package is available on npm.

Optional smoke test from a clean directory:

```sh
npx advisoryguard@0.1.0 --version
```
