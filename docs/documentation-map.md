# Documentation Map

NarrowCTI keeps documentation paths stable across historical and current
development releases. Current
operator documentation uses unversioned filenames, while versioned files preserve
release-specific snapshots and historical design evidence.

This avoids broken links in release notes while still giving operators and
contributors a clear public entry point.

## Public Product Path

Use these docs first:

- `getting-started.md`
- `deployment-operations.md`
- `configuration-reference.md`
- `architecture.md`
- `curation-decision-reference.md`
- `environment-profiles.md`
- `product-reference.md`
- `opencti-coverage-matrix.md`
- `analyst-review-api.md`
- `container-images.md`
- `opencti-compatibility.md`
- `security-quality-gates.md`
- `architecture-v1.0.md`
- `architecture-v0.9.md`
- `graph-promotion-v0.8.md`
- `infrastructure-correlation-v0.8.md`
- `opencti-coverage-matrix-v0.8.md`
- `analyst-review-v0.8.md`
- `curation-reporting-v0.8.md`
- `support-diagnostics-v0.8.md`
- `release-v1.0.1.md`
- `release-v1.0.0.md`
- `release-v0.9.0.md`
- `release-v0.8.0.md`

These files are product-facing and should be included in release source
archives.

## Release Status

| State | Version | Public evidence |
| --- | --- | --- |
| Latest published stable | `v1.0.1` | GitHub Release and immutable tag, published 2026-08-15. |
| Historical stable | `v1.0.0` | Previous GitHub Release and immutable tag, published 2026-07-13. |
| Historical tags | `v0.2.0` through `v0.9.0` | Tags exist; release pages exist for `v0.8.0` and `v0.9.0`. |

`product-reference.md` is the current product and version source of truth.
Versioned release notes remain historical or in-development evidence and must
not override this status table.

## Community Path

Use these docs for contribution, support and repository governance:

- `../CONTRIBUTING.md`
- `development-guide.md`
- `community-issue-triage.md`
- `repository-structure.md`
- `release-process.md`
- `community-governance.md`
- `community-standards.md`
- `../SUPPORT.md`
- `../SECURITY.md`
- `../CODE_OF_CONDUCT.md`

These files are public and should be included in release source archives.

## Architecture and Design Path

Current architecture:

- `architecture.md`
- `architecture-v1.0.md`
- `architecture-v0.9.md`
- `architecture-v0.8.md`
- `graph-promotion-v0.8.md`
- `infrastructure-correlation-v0.8.md`
- `opencti-rules-engine-v0.8.md`

Historical design context:

- `product-foundation-v0.3.md`
- `otx-adapter-foundation-v0.2.md`
- `multi-feed-expansion-v0.4.md`
- `gateway-runtime-v0.5.md`
- `quarantine-enrichment-v0.6.md`
- `architecture-v0.7.md`
- `graph-enrichment-v0.7.md`
- `mitre-curation-architecture-v0.7.md`
- `source-ingestion-modes-v0.7.md`
- `source-adapter-onboarding-v0.7.md`
- `contextual-scoring-reference-v0.7.md`

Historical architecture docs may remain public when they help contributors
understand why the product evolved into a gateway.

Reference docs such as `contextual-scoring-reference-v0.7.md` may remain in the
release source archive when they describe product design decisions that
contributors need to preserve.

## Current Reference Path

These unversioned files are the current source of truth for operators and public
repository readers:

- `architecture.md`
- `deployment-operations.md`
- `configuration-reference.md`
- `curation-decision-reference.md`
- `environment-profiles.md`
- `product-reference.md`
- `opencti-coverage-matrix.md`
- `analyst-review-api.md`
- `container-images.md`
- `opencti-compatibility.md`
- `security-quality-gates.md`
- `community-standards.md`

When behavior changes, update these files first. Add or retain a versioned
snapshot only when the release needs exact historical documentation.

## Release Notes Path

- `../CHANGELOG.md`
- `release-v1.0.1.md` (released)
- `release-v1.0.0.md` (released)
- `release-v0.9.0.md` (released)
- `release-v0.8.0.md`
- `release-v0.7.0.md`
- `release-v0.6.0.md`
- `release-v0.5.0.md`
- `release-v0.4.0.md`

Release notes should remain operator-facing. Lab logs and raw validation output
belong in development evidence, not public release notes.

## Development Evidence Path

Development evidence stays versioned when useful for maintainers, but many
evidence-heavy files are excluded from release source archives by
`.gitattributes`.

Examples:

- `operational-validation-v*.md`
- `*-official-connector-mapping-v*.md`
- `*-validation-v*.md`
- `metadata-validation-v*.md`
- `product-architecture-validation-v*.md`

These files should not be the first operator-facing documentation surface.

## Future Directory Migration

If the repository later moves docs into directories, use this target taxonomy:

```text
docs/product/
docs/architecture/
docs/community/
docs/development/
docs/validation/
docs/releases/
```

Do this only with a dedicated documentation migration commit, because many
release notes and historical docs currently reference root-level `docs/*.md`
paths.
