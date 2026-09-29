# Dekopon file provider

Content-based identification hints from a **bounded decoded prefix** of a chat
asset. Uses Dekopon SDK 0.18.0 asset handles, not inline bytes, paths, URLs or
subprocesses. Not the system `file` command or libmagic parity. No conversion,
extraction, structural validation, malware scanning or image decoding.

## Contract

Provider `file`; capability `file.identify`; effect `read-only`; risk `Low`.

```sh
file chat-asset:1
printf '%s' 'chat-asset:1' | file
file --help
```

`run-command` is pure: it proposes `{"data":"chat-asset:1"}` without opening
anything. Supply exactly one positional reference or one exact piped reference
(no trailing newline). `invoke` opens only an asset passed by the gateway for
that invocation, then reads up to **65,536 decoded bytes**, handling short reads.
No provider whole-file size ceiling remains: large assets are identified from
the prefix. The host's asset admission limits still apply (SDK 0.18.0: 8 MiB
decoded per asset). No data URLs or gateway expansion settings are supported.

Input is a closed object with required `data`: exact `chat-asset:<N>`, where N
is an unsigned 64-bit decimal id. Optional `filename` (256 UTF-8 bytes) and
`content_type` (127 UTF-8 bytes) remain ignored, untrusted hints. No control
characters; omitted/null are equivalent. Neither labels nor bytes are echoed.
Unknown fields, malformed references, paths and URLs return `invalid-input`.
Other capabilities return `unsupported-capability`. Open/read errors preserve
the SDK's stable error code, not host details; no retries or partial results.

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
    maxOutputBytes: 4096
```

Reading an opened input requires **no asset grant**, HTTP/storage grant, or
credentials. Reference presence is scoped to the current authorized invocation;
listing another asset does not authorize reading it. No `chatAssetInputs` or
`providerAttachments` route option is needed (both retired in core 0.18.0).
This repository does not change a deployment or prove live transport behavior.

## Build and validate

Rust 1.98.1; exact crates.io SDK/testkit 0.18.0 pins, locked graph. The component
imports only `dekopon:asset/asset@0.1.0` and exports `describe`, `invoke`,
`run-command`; no WASI imports. Provider/asset WIT mirrors match the resolved SDK.
Use ordinary Cargo with the machine's existing wrapper configuration; each
worktree owns its default `target/`.

```sh
cargo fmt --all --check
cargo deny --locked --all-features check bans licenses sources advisories
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings
bash scripts/build.sh
DEKOPON_PROVIDER_COMPONENT="$PWD/file-provider.wasm" cargo test --locked
```

Native injected-handle tests cover identification vectors, misleading hints,
short reads, EOF, 8 MiB input, exact prefix limits, failures and pure proposals.
The mandatory component tests require `DEKOPON_PROVIDER_COMPONENT` (never skip
when absent): imports/exports, pure CLI, invalid input, missing-reference refusal
and wire bounds. The published testkit cannot pass asset descriptors, so actual
handle reads are covered natively, not end-to-end through that testkit.
Fixture provenance: `tests/fixtures/README.md`.

Shared CI (`ci / validate`) includes independent reproducible builds. CI and
release callers track the shared workflows at `@main`. Release tags publish
`ghcr.io/dekopon-agents/provider-file`; only explicit tags trigger publication.

## License

MIT OR Apache-2.0; generated PNG fixture CC0-1.0. Dependency policy is checked
with cargo-deny; native broker-test dependencies are separate from the guest.
