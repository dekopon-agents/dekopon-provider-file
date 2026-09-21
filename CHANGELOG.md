# Changelog

## 0.2.0 — 2026-09-21

- Read a bounded 65,536-byte decoded prefix through SDK 0.18.0 asset handles.
- Accept only `chat-asset:<N>` inputs; remove inline data URLs and the 256 KiB whole-input ceiling.
- Report prefix-budget status instead of claiming whole-input size/completeness.
- Keep identification heuristics and untrusted hint handling; no asset grant required for reads.
- Add native fake-handle and component contract tests, and shared release workflows for the first tagged release.
