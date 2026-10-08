# Changelog

## 0.3.1 — 2026-10-08

- Pin the SDK and testkit to 0.36.0; the file identification contract and WIT surface remain unchanged.

## 0.3.0 — 2026-10-06

- File identification now uses the SDK 0.34.0 typed asset and stdio contract while retaining its bounded read-only metadata result.
- Pipe-only asset references are no longer accepted; use positional `file chat-asset:<N>` so admission sees the reference before authorization.
- File errors now use sanitized SDK failure codes and stderr instead of returning a JSON error.
- File manifest and component validation use the typed SDK contract instead of checked-in WIT mirrors and the old downloader.

## 0.2.0 — 2026-09-21

- Read a bounded 65,536-byte decoded prefix through SDK 0.18.0 asset handles.
- Accept only `chat-asset:<N>` inputs; remove inline data URLs and the 256 KiB whole-input ceiling.
- Report prefix-budget status instead of claiming whole-input size/completeness.
- Keep identification heuristics and untrusted hint handling; no asset grant required for reads.
- Add native fake-handle and component contract tests, and shared release workflows for the first tagged release.
