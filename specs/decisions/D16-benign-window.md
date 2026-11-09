---
id: D16
title: Benign window selection in the composer
status: open
affects: [SPEC-CORPUS 11, SPEC-CORPUS 15]
related: [D3, D15]
---
# D16. Benign window selection in the composer

## Context

Measured on the local v4 databases (`data/provenance/BENIGN_COMPOSITION_AUDIT_20261108.md` Sections 1 to 3):

- The composer anchors each source at its own earliest timestamp and uses events in order until the stream duration is filled (`_cycle_source`, `data/composer.py:257-295`). For a source whose span exceeds the stream, this selects the earliest window regardless of density. The 30-day stream's benign `syslog` is therefore 325 lines from May 2025 (a Debian installer log), 2.4% of the 13,599-line syslog corpus, while the dense December 2025 to February 2026 period (12,392 lines) is unused; the 2024 and 2026 `web_access` data (131,493 lines) is used in no stream.
- The kernel baseline is downsampled once to 24.2% by a hash keyed on the source timestamp (`:180`) before cycling (`:577-580`), so the same subset is repeated verbatim about 26 times in the 30-day stream and about 316 times in the 365-day stream (extrapolated, audit Section 8).
- `web_access` is 97.8% from calendar year 2013; benign authentication activity is 120 events per day because the benign build filtered real scanner traffic.

## Options

- Keep the earliest-timestamp anchor.
- A configurable window recorded in `composition_meta`, with the densest window as the default.
- Random window drawn from the stream seed (relevant under D15's scheduler).

## Recommendation

The analysis recommended a configurable window recorded in `composition_meta`, densest window by default, replacing the earliest-timestamp anchor.

## Decision

Open. Moot for the corrected baseline if it is collected as one contiguous run shorter than the longest stream.

## Consequences

Must be specified before the corrected baseline is cut into streams (D3). For the legacy corpus it determines whether any recomposition of v4.1 is meaningful.
