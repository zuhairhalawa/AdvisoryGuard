# Third-party notices

AdvisoryGuard itself is MIT-licensed (see `LICENSE`). It redistributes the following
third-party material.

## OSV schema (Apache License 2.0)

- File: `vendor/osv-schema/schema.json`, **unmodified**
- Source: https://github.com/ossf/osv-schema, `validation/schema.json`, tag `v1.9.2`,
  commit `c8a57bdc5b0bc54646e140cabbb7834bd0b5aec9`
- SHA-256: `15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653`
- Copyright the OpenSSF OSV schema authors. Licensed under the Apache License, Version 2.0; a copy
  is included at `vendor/osv-schema/LICENSE`. The upstream repository did not carry a separate
  NOTICE file at that commit.
- Verify against upstream at any time with `npm run verify:schema` (needs network).

## Runtime dependency

- [`ajv`](https://github.com/ajv-validator/ajv) (MIT) and its dependencies are installed through npm
  and not bundled into this package.

## Test data (repository only, not part of the npm package)

- `test/fixtures/real/` contains unmodified records from the GitHub Advisory Database
  (https://github.com/github/advisory-database), licensed CC BY 4.0. See
  `test/fixtures/real/README.md`.
