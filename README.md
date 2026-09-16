# Dekopon file provider

Bounded, content-based identification hints for supplied bytes. Pure Rust,
**zero component imports**: no filesystem access, URL fetching, subprocesses,
credentials, or gateway storage access. Not the system `file` command or full
libmagic parity. No conversion, extraction, file validation, malware scanning,
or image decoding.

**Current status:** foundational provider only. At core
[`fcb484bf17581735f47c89c1d7737729d28d6b6d`](https://github.com/dekopon-agents/dekopon/tree/fcb484bf17581735f47c89c1d7737729d28d6b6d),
gateway `chatAssetInputs` expands only model-readable PNG/JPEG/WebP/GIF assets.
Generic documents, HEIC/HEIF, AVIF and octet-stream chat attachments do **not**
reach this provider through that bridge. Direct caller-supplied data URLs work;
that does not establish an end-to-end arbitrary chat-file workflow or deployment
readiness. No deployment configuration has been changed.

## LLM-facing contract

Provider `file`; capability `file.identify`; effect `read-only`; risk `Low`.
Command word `file`. The complete JSON Schema is returned by `describe()` and
checked in [`tests/fixtures/manifest.json`](tests/fixtures/manifest.json).

```json
{"data":"data:text/plain;base64,aGVsbG8=","filename":"photo.heic","content_type":"image/heic"}
```

- `data` is required: `data:<type/subtype>;base64,<canonical padded standard base64>`.
  Empty bytes are allowed. No whitespace, MIME parameters, unpadded or URL-safe
  base64. The MIME label is required syntactically but **ignored** for detection.
- Optional `filename` (256 UTF-8 bytes) and `content_type` (127 UTF-8 bytes) are
  opaque hints; neither is opened, trusted, or echoed. No control characters.
  Omitted or null hints are equivalent. Extra fields are rejected in `invoke`.
- Maximum **whole input** is **262,144 decoded bytes (256 KiB)**, with a
  349,668-byte data URL ceiling. Larger inputs are refused, never silently
  clipped. This is not support for typical full-sized Mac photos. A future
  authorized bounded gateway prefix-read API would be needed for larger files;
  it is not implemented here, and manually supplying a prefix loses original
  file length/completeness information.
- Never supply a path or HTTP URL. An exact `chat-asset:1` marker is usable only
  when the gateway route expands it before invocation. Unresolved markers fail
  with `unresolved-asset`; no guest expansion or storage bypass exists.
- `input-too-large` explains the limit; `invalid-input` refuses malformed input;
  `unsupported-capability` refuses other operations. Errors do not echo bytes.
  Broker wire/fuel/memory refusals remain separate from provider errors.

Equivalent shell proposals (not host shell file access):

```sh
file 'data:text/plain;base64,aGVsbG8='
printf '%s' 'data:text/plain;base64,aGVsbG8=' | file
file chat-asset:1  # only a readable image <=256 KiB on an opted-in route
file --help
```

Arguments are after the `file` word; use exactly one positional DATA **or** piped
DATA. `run-command` only proposes, never detects or reads anything before broker
authorization. Unix `file` flags such as `--mime` are not implemented.

### Result

The example above returns `status: "identified"`, `mime: "text/plain"`,
`extension: "txt"`, `description: "Plain Text"`, and:

```json
{
  "input_bytes": 5,
  "bytes_supplied_to_detector": 5,
  "input_clipped": false,
  "evidence": "bounded-text-heuristic",
  "validated": false,
  "detector": "file-format/0.29.0; reader-txt"
}
```

A fixed `limitations` string accompanies every result. No raw content or
attachments are returned. `status` is `identified`, `empty`, or `unknown`;
empty/unknown have `extension: null` (not a guessed filename suffix). MIME and
human-readable description are the detector's hints, not security assertions.
`evidence` is `signature-heuristic`, `bounded-text-heuristic`, `empty-input`, or
`no-recognized-signature`. `bytes_supplied_to_detector` is **not** a claim that
all bytes were inspected internally or that the caller supplied a complete file.

## Detection limits

Uses [`file-format` 0.29.0](https://docs.rs/file-format/0.29.0/file_format/)
(MIT OR Apache-2.0), defaults disabled, only `reader-txt` enabled; no transitive
runtime dependencies for that crate. Signatures and the selected text heuristic
are not structural validation. Forged and truncated PNG/JPEG/PDF/ZIP or BMFF
headers can match. A positive result never implies valid codec data or safety.
Unknown does not imply corruption. No confidence probabilities are invented.

BMFF identification uses major brands at offset 8, without validating box sizes:

| Major brand | MIME hint |
| --- | --- |
| `heic`, `heix` | `image/heic` |
| `hevc`, `hevx` | `image/heic-sequence` |
| `mif1` | `image/heif` |
| `msf1` | `image/heif-sequence` |
| `avif` | `image/avif` |
| `avis` | `image/avif-sequence` |

Compatible brands do not refine `mif1` to HEIC/AVIF, and contradictory brands are
not rejected. Other upstream signatures also exist. Text fallback checks at most
16 lines / 65,536 bytes for ASCII/UTF-8 without disallowed controls; later binary
bytes may be missed. UTF-16/invalid UTF-8 are not generally recognized as text.
No full libmagic rules, recursive containers, encoding diagnosis or deep readers.

## Owner-controlled grants and routing

These are **fragments to adapt**, not a runnable deployment. Register the built
component as provider `file` in the owner's broker provider configuration. Include
`file.identify` in the catalog agent's `capabilities` and `file` in its
`providers`. Proposal surface alone grants no authority.

Broker constraint-set entry (under `constraintSets`):

```yaml
file.identify:
  provider: file
  effect: read-only
  risk: Low
  constraints:
    timeoutMs: 30000
    maxOutputBytes: 4096
```

No HTTP/storage/credential grants are required. Local tests exercise the default
64 MiB/store memory, 1 MiB wire input, 30-second timeout and 8-billion fuel ceiling;
a 1-million-fuel negative test proves the host can stop a maximum-size invocation.
No output contains unbounded input strings; outputs are small metadata objects.
Operator-wide constraints can still refuse inputs that fit provider limits.

Example narrow Cedar grants (declare/map these example identities owner-side):

```cedar
permit(principal == Dekopon::Principal::"analyst",
       action == Dekopon::Action::"agent.prompt",
       resource == Dekopon::Agent::"file-inspector")
when { context has via && context.via == "dekopond-gateway" };

permit(principal == Dekopon::Principal::"analyst",
       action == Dekopon::Action::"file.identify",
       resource == Dekopon::Provider::"file")
when { context has agent && context.agent == "file-inspector"
    && context has via && context.via == "dekopond-gateway" };
```

On an existing gateway route, opt into `chatAssetInputs: [file.identify]` only for
readable image input. This provides reach, **not a grant**. No
`providerAttachments` setting is necessary for metadata-only output. There are
no demonstrated `chat.asset.read`/`chat.asset.write` capabilities to grant.
The relevant current-core gates are
[`crates/dekopond/src/asset.rs`](https://github.com/dekopon-agents/dekopon/blob/fcb484bf17581735f47c89c1d7737729d28d6b6d/crates/dekopond/src/asset.rs#L462)
and
[`crates/dekopon-agent/src/attachment.rs`](https://github.com/dekopon-agents/dekopon/blob/fcb484bf17581735f47c89c1d7737729d28d6b6d/crates/dekopon-agent/src/attachment.rs#L549).

## Build and validate

Rust 1.98.1; SDK/testkit pinned to core Git revision
`fcb484bf17581735f47c89c1d7737729d28d6b6d` (0.16.0). No local-path dependencies.
`Cargo.lock` owns the resolved graph. Vendored provider WIT is byte-identical to
the pinned SDK. Primary artifact is an import-free `wasm32-unknown-unknown`
component exporting exactly `describe`, `invoke`, `run-command`.
`wasm32-wasip1` is **build-only portability evidence**, not the deployable
component or a request for WASI authority.

Install wasm-tools 1.259.0, Wasmtime 48.0.2 and cargo-deny 0.20.2. On this
workspace use `export RUSTC_WRAPPER=/opt/homebrew/bin/kache`; do not bypass a
wrapper failure. Do not share `CARGO_TARGET_DIR` across repositories.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings
cargo deny --all-features check bans licenses sources advisories
bash scripts/build.sh
wasm-tools validate file-provider.wasm
wasmtime run --invoke 'describe()' file-provider.wasm
DEKOPON_PROVIDER_COMPONENT="$PWD/file-provider.wasm" cargo test --locked
cargo build --locked --release --target wasm32-wasip1
```

The build script fetches only build tooling from the exact reusable CI pin
[`4cb9276ca166bee05c04e4c40ad9bca4b1f1065c`](https://github.com/dekopon-agents/provider-workflows/tree/4cb9276ca166bee05c04e4c40ad9bca4b1f1065c).
Tests require the fresh component and fail if its environment variable is absent;
they never skip runtime coverage. Tests assert exactly zero imports, three
exports, broker invocation/CLI, maximum-size input, negative fuel/wire limits,
HEIC/AVIF distinctions, misleading hints, truncation, empty/unknown, text-probe
limits and malformed input. The original generated PNG fixture and synthetic
vectors have provenance in [`tests/fixtures/README.md`](tests/fixtures/README.md).
No private photos or paid services are used.

Shared CI (`ci / validate`) runs on main pushes and pull requests, including
independent reproducible builds. This repository defines **no release or tagging
workflow**. A main push does not tag, release or deploy. Local checks do not prove
remote CI or production integration. Preserve validation receipts, then delete
only this repository's inactive ignored `target/` after checking active processes.

## License

Source: MIT OR Apache-2.0; see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Generated PNG: CC0-1.0. Dependency policy is
checked with `cargo deny`; native broker-test dependencies are separate from the
import-free guest's dependency graph.
