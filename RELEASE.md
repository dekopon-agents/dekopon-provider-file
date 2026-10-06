# Releasing the file provider

The provider repository's `.github/workflows/ci.yml` and `release.yml` call
`dekopon-agents/provider-workflows` at `@main`. A reviewed, merged main commit
with package version 0.3.0 is tagged **once** with an annotated `v0.3.0` tag;
the tag workflow is the sole publisher. Do not manually publish, replace an
existing tag or version, or treat a local build as a release artifact.

The shared workflow verifies the tag, package version and main ancestry, runs
format/dependency/lint checks, builds and tests the component, generates a
CycloneDX SBOM, attests the artifacts, publishes an OCI image and finalizes the
GitHub release. A stable release is marked **latest** (prereleases are not).
The release has exactly three assets:

- `file-provider.wasm`
- `file-provider.wasm.sha256`
- `file-provider.cdx.json`

Download all three assets into a separate scratch directory. In that directory:

```sh
shasum -a 256 -c file-provider.wasm.sha256
gh attestation verify file-provider.wasm \
  -R dekopon-agents/dekopon-provider-file --format json \
  --signer-repo dekopon-agents/provider-workflows \
  --source-ref refs/tags/v0.3.0 --source-digest <main-merge-SHA>
crane manifest ghcr.io/dekopon-agents/provider-file:0.3.0
crane digest ghcr.io/dekopon-agents/provider-file:0.3.0
```

Inspect the verified attestation JSON: its subject SHA-256 must equal the
sidecar's wasm SHA-256, its source ref must be `refs/tags/v0.3.0`, and its source
digest must be the tagged main merge commit. The `crane manifest` must contain
exactly one layer of media type `application/wasm`, whose digest is
`sha256:<attested-wasm-SHA-256>`. The distinct `crane digest` output is the
immutable OCI **manifest** digest to pin in deployments, not the wasm layer
SHA. Stop on any absent or mismatched proof; do not republish or retag.
