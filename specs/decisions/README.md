# Decision Register

This register records every design decision that governs the security-gym specifications (`specs/SPEC-ENV.md`, `specs/SPEC-CORPUS.md`, `specs/SPEC-BENCH.md`). Its table is the single source of truth for verdicts; it replaces Section 14 of the former `spec.md`. Each row links to a record holding the context, options, recommendation, decision, and consequences.

**Status vocabulary.** `open`: no verdict; the record carries the analysis's recommendation only. `decided`: the author has ruled; the verdict is binding on the specifications. `partially decided`: the main question is decided and one or more named sub-items remain open.

**Authority.** Verdicts are the author's. Recommendations are analysis, not verdicts, and an open row is never resolved by editing its recommendation.

| ID | Title | Status | Decided | Affects | Verdict or recommendation |
|---|---|---|---|---|---|
| [D1](D01-session-model.md) | Session model | decided | 2026-11-08 | SPEC-CORPUS 7, 12; SPEC-ENV 4 | Option B: symmetric process-subtree session, materialized, never used for labeling; schema version 3 |
| [D2](D02-ebpf-purpose.md) | Purpose of the eBPF channels | decided | 2026-11-08 | SPEC-CORPUS 5; SPEC-BENCH 3, 4 | Purpose 1 (detection and attribution) is the headline; Purposes 2 and 3 adopted; repeat Exp 13 under honest delivery |
| [D3](D03-ebpf-remediation-recollection.md) | eBPF remediation and background workload | partially decided | 2026-11-08; 2026-11-09 | SPEC-CORPUS 4, 5, 9, 15 | Re-collect on Isildur, three-host merge retired, new dataset DOI; busy host with lab-generated benign traffic. Open: workload composition (a, c, or a with c) |
| [D4](D04-system-stats.md) | The `system_stats` channel | open | | SPEC-ENV 5.4 | Remove unless a real series is captured |
| [D5](D05-isolate-exit.md) | Exit path for `isolate` | open | | SPEC-ENV 7.3, 6 | TTL plus explicit de-isolation path |
| [D6](D06-risk-score.md) | Status of `risk_score` | open | | SPEC-ENV 6, 8.5 | Opt-in auxiliary declared outside the control objective |
| [D7](D07-defense-state-fields.md) | Defense-state fields and hybrid encoding | open | | SPEC-ENV 5.5, 5.7 | Freeze the six fields plus TTL remaining; must also report D11's typed controls |
| [D8](D08-info-evaluation-only.md) | `info` evaluation-only | open | | SPEC-ENV 10 | Yes; mirror any agent-usable field into an observation channel |
| [D9](D09-reward-matrix.md) | Configurable reward matrix | open | | SPEC-ENV 8.7, 8; SPEC-BENCH 6 | Required before the control benchmark; the alignment and repeated-control fixes precede any baseline |
| [D10](D10-control-protocol.md) | Control metrics and pinned protocol | open | | SPEC-BENCH 3, 5, 6, 7, 8 | Required for "benchmark" to be accurate; publication blocker |
| [D11](D11-process-level-actions.md) | Process-level actions and `report` | partially decided | 2026-11-08 | SPEC-ENV 6, 6.3, 7, 8.7 | Kill process, close port, disable account in scope; typed target; `Discrete(6)` not frozen. Open: `report` before or after the freeze |
| [D12](D12-kernel-labeling-rule.md) | Kernel-event labeling rule | partially decided | 2026-11-08 | SPEC-CORPUS 6, 11, 13, 15 | Ancestry test; composer carries attack-caused events; H5 checks in the validator. Open: legacy-label disposition; legacy kernel-targeting results |
| [D13](D13-instance-identity.md) | Attack instance definition and identifiers | open | | SPEC-CORPUS 6, 10, 11, 12; SPEC-BENCH 5; SPEC-ENV 10 | Three identifiers minted outside the telemetry: `recording_id`, `stage_id` (harness), `instance_id` (scheduler) |
| [D14](D14-artifact-manifest.md) | Artifact manifest and download channel | open | | SPEC-CORPUS 10, 14 | One digest-verified manifest consumed by `download.py`; retire GitHub Releases |
| [D15](D15-composition-locus.md) | Composition locus and adversary model | open | | SPEC-CORPUS 11; SPEC-ENV 9; SPEC-BENCH 4, 6 | Seeded open-loop runtime scheduler; pinned streams are the same code path materialized; no adaptive adversary |
| [D16](D16-benign-window.md) | Benign window selection | open | | SPEC-CORPUS 11, 15 | Configurable window recorded in `composition_meta`, densest by default |
| [D17](D17-format-symmetry.md) | Source and surface-format symmetry | open | | SPEC-CORPUS 13, 15; SPEC-ENV 5.7 | Data side resolved by D3; validator separability gate required |
| [D18](D18-contribution-model.md) | Contribution model | decided | 2026-11-09 | SPEC-CORPUS 8, 10, 14 | Scenario packages by pull request, run by maintainers on the reference target only |
| [D19](D19-recon-network-source.md) | Host network-layer source | decided | 2026-11-09 | SPEC-CORPUS 5, 8 | None; reconnaissance is what services and the syscall surface observe |
| [D20](D20-attribution-policy.md) | Attribution policy | open | | SPEC-CORPUS 6, 12, 13; SPEC-ENV 8; SPEC-BENCH 5 | Pending fact-finding; two author decisions (definition of malicious, scoring of non-binary classes) |

## Recorded recommendations from the 2026-11-07 review (not verdicts)

Three agent-conducted reviews, each by a fresh AI agent given the repository and prompted in one role (RL researcher, staff engineer, doctoral supervisor), unanimously recommended refactoring the environment in place rather than rebuilding it; the author accepted that direction. These were not reviews by people. Two further recommendations from the supervisor-role review were presented to the author and not contested; they are recorded here so they are not lost, and carry no verdict.

- **Freeze.** No new features, dataset versions, or DOIs until the register resolves. Infrastructure and test work (the conformance suite, the manifest, validator checks, the reward-alignment fixes) is compatible with it.
- **Scope.** The core deliverable is the environment, the control benchmark, and one learning control baseline on the 7-day and 30-day streams. Deferred: NetFlow, LSM enforcement, the streaming server (ROADMAP Phase 7), the `report` action (D11 sub-item), and an RL-versus-LLM comparison. The same review listed publication obligations: Zenodo errata and deprecation notes on the superseded records (SPEC-CORPUS 14) and a downstream-consumer audit (TODO.md staleness sections).

## Decision order

Facts are gathered by the agent; verdicts are the author's. With D1, D2, D3, D11, D12, D18, and D19 settled, the frontier is: D13, D15, D14, D4, D6, D8, D20, and the D3 workload sub-item; then D9, D5, D7 (which depends on D11's typed targets), D16, D17, and the D11 `report` sub-item; then D10, which depends on all of the above. The freeze conflict below is asked with D10. D13, D15, and D20 are needed before the re-collection campaign plan is written.

## Sequencing

**Conflict recorded, not resolved; asked with D10.** If the process-level actions (D11) land after the first protocol freeze, either protocol version 1 declares the address-level action set, with the typed target as a named extension point, and the process-level actions are published under protocol version 2 with their own baselines; or the freeze waits for D11. Relatedly, benchmark numbers produced before the corrected corpus is released are produced either on a pre-release of it or on the legacy streams with the D12 caveat.
