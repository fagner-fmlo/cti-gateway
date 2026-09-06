# Container Images

This document defines the NarrowCTI Gateway container image policy.

## Image Name

The canonical Community Edition gateway image is:

```text
ghcr.io/narrowcti/narrowcti-gateway
```

Local development and lab validation can continue to use:

```text
narrowcti/gateway:local
```

The Compose deployment template reads the image from:

```text
NARROWCTI_GATEWAY_IMAGE
```

## Tag Policy

| Tag | When it is published | Stability |
| --- | --- | --- |
| `latest` | Push to `main` | Moving stable branch tag. |
| `main` | Push to `main` | Moving branch tag. |
| `0.8.0` | Git tag `v0.8.0` | Immutable release tag. |
| `0.8` | Git tag `v0.8.0` | Moving latest patch in minor line. |
| `0` | Git tag `v0.8.0` | Moving latest release in major line. |
| `0.9.0` | Git tag `v0.9.0` | Immutable release tag after publication. |
| `0.9` | Git tag `v0.9.0` | Moving latest patch in minor line after publication. |
| `1.0.0` | Git tag `v1.0.0` | Historical immutable release tag published 2026-07-13. |
| `1.0.1` | Git tag `v1.0.1` | Historical immutable release tag published 2026-08-15. |
| `1.0` | Git tag `v1.0.1` | Historical moving patch line. |
| `1.1.0` | Git tag `v1.1.0` | Immutable release tag published 2026-09-06. |
| `1.1` | Git tag `v1.1.0` | Moving latest patch in minor line. |
| `1` | Git tag `v1.1.0` | Moving latest release in major line. |
| `sha-<short-sha>` | Every published build | Immutable traceability tag. |

Operators should pin production-like environments to an immutable release tag,
for example:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.1.0
```

Use `latest` only when intentionally tracking the newest stable `main` build.

## Local Build

```powershell
docker build -f Dockerfile.gateway -t narrowcti/gateway:local .
```

Then validate:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local
```

## Publish Workflow

The GitHub Actions workflow in `.github/workflows/container-image.yml` builds and
scans candidates for pull requests, `dev`, `main` and feature branches. It
publishes to GitHub Container Registry only on `main` and semantic version tags.

Publication requires:

- a clean Docker build from `Dockerfile.gateway`;
- CI validation kept green before creating a release tag;
- the protected GitHub `release` environment approved for publication;
- job-scoped write permission to GitHub Packages, available only to the
  publication job.

The v1.1 publication gate uses this order for the exact candidate
image:

```text
build -> smoke test -> Trivy scan -> CycloneDX SBOM -> exact candidate artifact
  -> protected release approval -> registry login -> push
```

Pull requests and `dev` builds exercise the build, smoke, scan and SBOM path but
do not publish stable image tags. `main` and version tags first retain the exact
scanned candidate as a short-lived artifact. A separate publication job then
loads that same candidate and publishes only after the `release` environment
allows it. See `docs/security-quality-gates.md` for the blocking policy.

Docker Hub mirroring can be added later with explicit repository secrets and the
same tag policy. Until then, GHCR is the canonical public registry.
