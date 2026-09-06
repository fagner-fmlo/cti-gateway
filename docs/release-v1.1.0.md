# NarrowCTI v1.1.0 Release Notes

## Status

Status: release candidate.

The candidate is prepared on `release/v1.1.0` from the reviewed `dev` branch.
It becomes an official release only after the protected `dev -> main` flow,
required checks, the immutable `v1.1.0` tag and the GitHub Release are complete.
Until then, `v1.0.1` remains the latest published stable release.

## Release Theme

v1.1.0 adds evidence-driven detection relationships to the OpenCTI graph while
preserving analyst visibility when a rule cannot be mapped to ATT&CK. It also
includes the reviewed dependency maintenance batch already integrated into
`dev`.

## Highlights

- Create deterministic `Indicator --detects--> Attack-Pattern` candidates for
  MISP Sigma/YARA rules only when an explicit ATT&CK tag, reference or other
  trusted mapping is present.
- Keep audit, dry-run, export and idempotency controls authoritative for graph
  relationship promotion.
- Preserve detection-rule report context when no ATT&CK relationship can be
  resolved; absence of a mapping is reported as a coverage boundary, not a
  reason to discard the rule.
- Carry the reviewed Dependabot maintenance updates for the OpenCTI client,
  msgpack, Ruff and container build/SBOM actions.

## Evidence Boundary

The gateway does not relate a rule to every technique that merely co-occurs in
the same event. A relationship is eligible only when the source contains an
explicit, deterministic mapping. This keeps the graph explainable and avoids
manufacturing defensive coverage.

## Upgrade Guidance

The release does not require an environment-variable migration or state reset.
Existing graph objects are not rewritten automatically. Operators should keep
stable deployments pinned to the immutable release image after publication:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.1.0
```

The moving `latest` line must not be treated as the immutable release until the
protected publication workflow completes.

## Validation Record

- Dependabot batch PR #65 was reviewed and integrated into `dev`.
- The existing local validation evidence for the integrated code passed 544
  unit tests, Ruff, Bandit and strict dependency audits.
- The protected CI, security, DAST and container-image gates for the release
  candidate must pass before promotion and publication. Their run links will
  be added to this document before the final tag.

## Traceability

- Source branch: `release/v1.1.0`, created from `dev`.
- Detection relationship feature: commit `2bc86be` / PR #62.
- Unmapped-rule context fix: commit `2a76e97` / PR #63.
- Dependency maintenance batch: commit `16ed640` / PR #65.
- Promotion PR to `dev`: [#67](https://github.com/NarrowCTI/narrowcti/pull/67).
- Promotion PR to `main`: [#68](https://github.com/NarrowCTI/narrowcti/pull/68).
- Git tag and release commit: to be recorded only after publication.

The intended release path remains:

```text
release/v1.1.0 -> dev -> main -> v1.1.0 tag -> GitHub Release
```

## Known Boundaries

- Detection rules without an explicit ATT&CK mapping remain visible but are
  not assigned a fabricated `detects` relationship.
- This release does not add a Mitre D3FEND connector.
- Historical OpenCTI objects are not backfilled automatically; reprocessing is
  required when an existing object should receive the new relationship.

## License

NarrowCTI Community Edition remains distributed under the Apache License 2.0.
