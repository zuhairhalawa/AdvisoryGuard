# Releasing

A version tag runs [`release.yml`](../.github/workflows/release.yml), which checks the release and uploads the package to npm's stage queue with provenance. Nothing becomes public until a maintainer approves it with 2FA.

**Status:** the checks and a dry run of the upload have run on GitHub. The real upload has not run yet, so the first release through this workflow is also its first real test. Versions 0.2.0 and 0.3.0 were staged by hand and have no provenance.

## Steps

### 1. Prepare the version

In a pull request, update the version with `npm version <version> --no-git-tag-version --ignore-scripts`, the changelog and the release notes. Merge it once CI passes.

### 2. Allow this workflow to upload (first time, or if it has expired)

Do this right before tagging. **npm removes a new trusted publisher if it has no successful publish within 2 days.** npm also does not check these values when you save them, so a mistake only shows up when the workflow runs.

On npmjs.com, go to the package's Settings, then Trusted Publisher, then GitHub Actions:

| Field | Value |
| --- | --- |
| Organization or user | `zuhairhalawa` |
| Repository | `AdvisoryGuard` |
| Workflow filename | `release.yml` |
| Environment name | `npm-release` |
| Allowed actions | Leave `npm publish` and `npm dist-tag` unticked, so only staging is allowed |

Or, with npm 11.15 or later:

```sh
npm trust github advisoryguard --file release.yml --repo zuhairhalawa/AdvisoryGuard --env npm-release --allow-stage-publish
```

### 3. Tag the merged commit

```sh
git fetch origin
git tag -a v<version> <merge-commit> -m "AdvisoryGuard v<version>"
git push origin refs/tags/v<version>
```

The workflow stops if the tag does not match `package.json`, if the commit is not on `main`, or if that version is already on npm. Do not move a tag or reuse a version.

### 4. Approve

The run's summary shows the tarball's sha1 and integrity. Compare the sha1 with the entry on the [Staged Packages page](https://www.npmjs.com/settings/zuhairhalawa/staged-packages), then approve it with your key.

Do not use a recovery code for this. npm places a 72-hour hold on publishing after one is used.

### 5. Check and announce

```sh
npm view advisoryguard@<version> version dist.shasum dist.integrity dist.attestations
npx advisoryguard@<version> --version
```

Then publish the GitHub release, attaching the `tarball` artifact from the workflow run.

## If something goes wrong

- **The upload fails with an authentication error:** the trusted publisher is probably missing, expired or has a wrong value. Fix it, delete nothing, and re-run the failed job. The tag does not need to change.
- **The checks fail:** fix the problem under a new version. Do not move the tag.
- **The staged package is wrong:** reject it on the Staged Packages page, and release a new version.

## Checking the workflow without releasing

Pull requests that change `release.yml`, and manual runs from the Actions tab, do everything except the upload. They end with `npm stage publish --dry-run`.
