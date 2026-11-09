---
id: D14
title: Artifact manifest and download channel
status: open
affects: [SPEC-CORPUS 10, SPEC-CORPUS 14]
related: [D3, D15]
---
# D14. Artifact manifest and download channel

## Context

The downloader (`src/security_gym/scripts/download.py:13`, `:104-121`) points at GitHub Releases and verifies nothing, while the canonical artifacts are the Zenodo and HuggingFace `.db.zst` archives. `croissant.json` carries real checksums for all six entries since 2026-07-26 but nothing consumes them. The composer records input database paths but no digests, version, or commit (`data/composer.py:708-716`). This is the process hole behind both stale-archive incidents (`data/provenance/V4_ARCHIVE_STALENESS_20260726.md`, `V3_ARCHIVE_STALENESS_20260831.md`).

## Options

- Promote `croissant.json` to the manifest of record and have `download.py` verify against it.
- Add a dedicated `MANIFEST.yaml` (digests, sizes, versions, DOI) consumed by `download.py`, with `croissant.json` generated from it.
- Retire or keep GitHub Releases as a channel.

In every option the manifest is regenerated from the live databases at publication. The entry fields, downloader behavior, and tests that hold under every option are specified in SPEC-CORPUS CORPUS-R-141 (a practice adopted from ACES Evals, SPEC-BENCH Appendix A.1: canonical URL, record or revision, archive and decompressed sha256 and sizes, event count, composition configuration and seed, composer version; verify before and after decompression; replace stale files; `.verified` sidecar).

## Recommendation

The analysis recommended one digest-verified manifest consumed by `download.py`, and retiring GitHub Releases as a channel. Which file serves is the decision; whether to have one is not (SPEC-BENCH Appendix A.1).

## Decision

Open. Independent of all other rows.

## Consequences

Under the 2026-11-09 capture architecture each recording carries its own manifest (SPEC-CORPUS 10); the release manifest aggregates recording and stream digests (SPEC-CORPUS 14).
