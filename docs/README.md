# NarrowCTI Documentation

This directory contains public product documentation, community documentation
and selected development evidence.

Start with `documentation-map.md` when deciding which document belongs in a
release archive or community-facing page.

## Product Entry Points

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
- `curation-reporting-v0.8.md`
- `support-diagnostics-v0.8.md`

## Community and Governance

- `documentation-map.md`
- `repository-structure.md`
- `release-process.md`
- `community-governance.md`
- `community-standards.md`
- `../CONTRIBUTING.md`
- `development-guide.md`
- `community-issue-triage.md`
- `../SUPPORT.md`
- `../CODE_OF_CONDUCT.md`
- `../SECURITY.md`

## Architecture and Design

- `architecture.md`
- `architecture-v1.0.md`
- `architecture-v0.9.md`
- `analyst-review-api.md`
- `opencti-compatibility.md`
- `architecture-v0.8.md`
- `graph-promotion-v0.8.md`
- `infrastructure-correlation-v0.8.md`
- `opencti-rules-engine-v0.8.md`
- `mitre-curation-architecture-v0.7.md`
- `contextual-scoring-reference-v0.7.md`
- `source-ingestion-modes-v0.7.md`
- `source-adapter-onboarding-v0.7.md`

## Release Notes

- `../CHANGELOG.md`
- `release-v1.0.1.md` (released)
- `release-v1.0.0.md` (released)
- `release-v0.9.0.md` (released)
- `release-v0.8.0.md` (released)
- `release-v0.7.0.md`
- `release-v0.6.0.md`
- `release-v0.5.0.md`
- `release-v0.4.0.md`

## Release Status

The release sequence is `v0.8.0` -> `v0.9.0` -> `v1.0.0` -> `v1.0.1`. The
first three are historical or baseline milestones, while `v1.0.1` is the
current patch release for the initial Community Edition milestone.

`v1.0.1` is the latest published stable release, dated 2026-08-15. Tags
`v0.2.0` through `v1.0.0` remain historical version snapshots, with GitHub
Release pages for `v0.8.0`, `v0.9.0`, `v1.0.0` and `v1.0.1`. See
`product-reference.md` for the single current status table and
`release-process.md` for publication order.

## Release Snapshots

Versioned documents preserve release-specific behavior and design evidence.
Use the unversioned product entry points for the current operator path.

- `architecture-v0.8.md`
- `deployment-operations-v0.8.md`
- `configuration-reference-v0.6.md`
- `configuration-reference-v0.5.md`

## Development Evidence

These files are useful for maintainers and contributors, but should not be the
first documentation surface for operators:

- `operational-validation-v*.md`
- `*-official-connector-mapping-v*.md`
- `*-validation-v*.md`
- `product-architecture-validation-v*.md`
- `metadata-validation-v*.md`

Many development-evidence files are excluded from release source archives by
`.gitattributes`.

## Release Archive Policy

GitHub releases generated from tags expose source archives. NarrowCTI keeps
source code, tests, deployment templates, public product docs and community
governance files in those archives.

Local state, local agent instructions, secrets, raw feed payloads and selected
development evidence are excluded through `.gitignore`, `.dockerignore` and
`.gitattributes`.
