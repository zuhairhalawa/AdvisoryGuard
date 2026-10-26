# Publishing checklist for v0.1.0 (maintainer only)

Nothing here has been run. Do these steps yourself, in order.

## 1. Create and push the repository

Repository name: `AdvisoryGuard` under `zuhairhalawa` (public, MIT).

Description (GitHub "About"):

> Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited.

Topics: `osv`, `ghsa`, `github-advisory-database`, `security-advisories`, `cvss`, `vulnerability`,
`supply-chain-security`, `json-schema`, `cli`, `nodejs`, `typescript`

```sh
git init -b main
git add .
git status            # confirm no node_modules/, dist/, .tmp/ or *.tgz are staged
git commit -m "AdvisoryGuard v0.1.0"
gh repo create zuhairhalawa/AdvisoryGuard --public --source . --description "Offline CLI that validates OSV / GitHub Security Advisory JSON against the official OSV schema and flags accidental data loss, such as deleted CVSS vectors, when an advisory is edited." --push
gh repo edit zuhairhalawa/AdvisoryGuard --add-topic osv --add-topic ghsa --add-topic github-advisory-database --add-topic security-advisories --add-topic cvss --add-topic vulnerability --add-topic supply-chain-security --add-topic json-schema --add-topic cli --add-topic nodejs --add-topic typescript
```

In the repository settings, enable **Security > Private vulnerability reporting** (SECURITY.md
refers to it).

## 2. Wait for CI

The first push runs `.github/workflows/ci.yml` (Ubuntu/macOS/Windows x Node 22/24, packed-tarball
runtime check on Node 20, `npm audit`, vendored-schema verification). Do not tag until it is green;
fix anything the Linux/macOS runners reveal (they have not been run yet).

## 3. Tag and release

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
gh release create v0.1.0 --title "AdvisoryGuard v0.1.0" --notes-file docs/release-notes-v0.1.0.md
```

## 4. Publish to npm (needs your npm login / 2FA)

```sh
npm view advisoryguard        # should still 404 (name free); re-check right before publishing
npm login
npm publish --dry-run         # review the file list: dist/, vendor/, README, LICENSE, notices, changelog
npm publish
npx advisoryguard@0.1.0 --version   # smoke-test from a clean directory
```

Then remove the "Status" note from the README ("If `npm install advisoryguard` does not find the
package yet ...") and commit.
