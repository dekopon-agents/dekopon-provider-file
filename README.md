# Dekopon file provider

Content-based identification hints from a **bounded decoded prefix** of a chat
asset. Uses Dekopon SDK 0.36.0 asset handles, not inline bytes, paths, URLs or
subprocesses. Not the system `file` command or libmagic parity. No conversion,
extraction, structural validation, malware scanning or image decoding.

## Contract

Provider `file`; capability `file.identify`; effect `read-only`; risk `Low`.

```sh
file chat-asset:1
file --help
```

`run-command` is pure: it proposes `{"data":"chat-asset:1"}` without opening
anything. Supply a positional `file chat-asset:<N>` reference. Pipe-only
references are refused: the gateway must see the reference in the proposal
before authorization, while `run-command` receives only a pipe-present boolean.
No stdin is read before authorization and no asset listing bypasses admission.
`invoke` opens only an asset passed by the gateway for that invocation, then
reads up to **65,536 decoded bytes**, handling short reads. No provider
whole-file size ceiling remains: large assets are identified from the prefix.
The host's asset admission limits still apply. No data URLs or gateway
expansion settings are supported.

Input is a closed object with required `data`: exact `chat-asset:<N>`, where N
is an unsigned 64-bit decimal id. Optional `filename` (256 UTF-8 bytes) and
`content_type` (127 UTF-8 bytes) remain ignored, untrusted hints. No control
characters; omitted/null are equivalent. Neither labels nor bytes are echoed.
Unknown fields, malformed references, paths and URLs return `invalid-input`.
Other capabilities return `unknown-capability`. Open/read errors preserve
the SDK's stable error code, not host details; no retries or partial results.
Success writes one newline-terminated JSON object to stdout; failures write
sanitized stderr and exit nonzero, including a closed stdout.

### Result

```json
{
  "status": "identified",
  "mime": "text/plain",
  "extension": "txt",
  "description": "Plain Text",
  "bytes_supplied_to_detector": 5,
  "prefix_limit_reached": false,
  "evidence": "bounded-text-heuristic",
  "validated": false,
  "detector": "file-format/0.29.0; reader-txt"
}
```

A fixed `limitations` string accompanies every result. `status` is `identified`,
`empty`, or `unknown`; empty/unknown have `extension: null`. Evidence is
`signature-heuristic`, `bounded-text-heuristic`, `empty-input`, or
`no-recognized-signature`. `prefix_limit_reached` means the read budget was
filled, **not** that more bytes exist. No extra EOF probe is made at the bound.
`bytes_supplied_to_detector` is neither whole-file size nor proof all supplied
bytes were inspected. The former `input_bytes` and `input_clipped` fields are
removed because they would misleadingly describe a complete input. Only
metadata is returned, never attachments or asset bytes.

## Detection limits

Uses `file-format` 0.29.0 with defaults disabled and only `reader-txt` enabled.
Headers can be forged or incomplete. A match does not prove valid codec data or
safety; unknown does not imply corruption. Text fallback checks at most 16
lines / 65,536 bytes for ASCII/UTF-8; later binary data may be missed. UTF-16 and
invalid UTF-8 are not generally recognized as text. No deep/recursive readers.

BMFF identification uses major brands at offset 8 without validating box sizes:
`heic`/`heix` → HEIC, `hevc`/`hevx` → HEIC sequence, `mif1` → HEIF,
`msf1` → HEIF sequence, `avif` → AVIF, `avis` → AVIF sequence. Compatible brands
do not refine `mif1` to HEIC/AVIF; contradictory brands are not rejected.
Filename and declared MIME never influence the detector.

## Owner-controlled grants

Register the component as provider `file` and authorize `file.identify` with
matching broker constraint sets and Cedar policy. Example constraint-set entry:

```yaml
file.identify:
  provider: file
  effect: read-only
  risk: Low
  constraints:
    timeoutMs: 30000
```

Reading an opened input requires **no asset grant**, HTTP/storage grant, or
credentials. Reference presence is scoped to the current authorized invocation;
listing another asset does not authorize reading it. No `chatAssetInputs` or
`providerAttachments` route option is needed.
This repository does not change a deployment or prove live transport behavior.

## Build and validate

Rust 1.98.1; exact crates.io SDK/testkit 0.36.0 pins, locked graph. The component
imports only `dekopon:asset/asset@0.1.0` and `dekopon:stdio/streams@0.1.0`,
exports `dekopon:provider@0.4.0`; no WASI imports. The SDK owns the WIT.
Use ordinary Cargo with the machine's existing wrapper configuration; each
worktree owns its default `target/`.

```sh
cargo fmt --all --check
cargo deny --all-features check bans licenses sources advisories
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --package dekopon-file-provider --lib --target wasm32-unknown-unknown -- -D warnings
../provider-workflows/build.sh
shasum -a 256 -c file-provider.wasm.sha256
DEKOPON_PROVIDER_COMPONENT="$PWD/file-provider.wasm" cargo test --locked --workspace
```

Native injected-handle tests cover identification vectors, misleading hints,
short reads, EOF, 8 MiB input, exact prefix limits, failures and pure proposals.
The mandatory component tests require `DEKOPON_PROVIDER_COMPONENT` (never skip
when absent): typed conformance, exact imports/export, missing-descriptor refusal
and invalid-reference refusal. The published testkit cannot pass asset
descriptors, so actual handle reads are covered natively, not end-to-end through
that testkit. The old hand-authored manifest fixture was dropped because the
SDK typed manifest and component conformance now establish the single contract.
Fixture provenance: `tests/fixtures/README.md`.

Shared CI (`ci / validate`) checks formatting, dependency policy, host and wasm
clippy, the built component and checksum, locked tests (including component
conformance against that built wasm), and the CycloneDX SBOM. Additional local
pre-push checks include rustdoc with warnings denied, WIT decode/validation and
fixture provenance. CI and release callers track the shared workflows at
`@main`. Annotated release tags publish `ghcr.io/dekopon-agents/provider-file`;
only explicit tags trigger publication. See [RELEASE.md](RELEASE.md) for the
three release assets, attestation and OCI manifest verification. This repository
does not establish live asset-read behavior: the testkit conformance exercises
component imports/export and denial, while actual reads use native fake handles.

## License

MIT OR Apache-2.0; generated PNG fixture CC0-1.0. Dependency policy is checked
with cargo-deny; native broker-test dependencies are separate from the guest.
