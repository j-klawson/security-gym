---
id: SPEC-INDEX
title: security-gym specification set
status: draft
date: 2026-11-09
replaces: spec.md (draft of 2026-11-08, commit a70aeda)
---

# security-gym Specification Set

## Abstract

This directory specifies security-gym, a Gymnasium-compatible, trace-driven replay
environment for continual reinforcement learning on host security telemetry. The
specification is divided into three documents, each covering one coherent surface,
and a register of decision records that holds the rationale, options, and verdicts
the documents cite. It replaces the single draft `spec.md` of 2026-11-08, whose
as-built claims were verified against the code on 2026-11-08 and corrected here.

## Status of This Set

Draft. The documents state the target behavior of the environment and the corpus.
Where present behavior differs from a requirement, the requirement carries a
conformance note. Decisions are made by the author; documents and records written
by an agent present analysis and recommendations and never record a verdict the
author has not given.

## 1. Documents

| ID | File | Surface | Primary code |
|---|---|---|---|
| SPEC-ENV | [SPEC-ENV.md](SPEC-ENV.md) | Environment contract: observation, action, defense state, reward, step semantics, `info`, configuration | `src/security_gym/envs/`, `src/security_gym/adapters/` |
| SPEC-CORPUS | [SPEC-CORPUS.md](SPEC-CORPUS.md) | Corpus construction: reference target, recorder, attribution and labels, sessions, scenario packages, benign workload, recordings, composition, schema, validation, release | `server/`, `attacks/`, `scripts/`, `src/security_gym/data/`, `src/security_gym/parsers/` |
| SPEC-BENCH | [SPEC-BENCH.md](SPEC-BENCH.md) | Control benchmark: definition, configuration, control metrics, protocol, baselines, reporting | `examples/`, evaluation runner (not yet built) |
| Decisions | [decisions/README.md](decisions/README.md) | Register D1 to D20; one record per decision | none |

Dependency order: SPEC-CORPUS produces the streams SPEC-ENV consumes; SPEC-BENCH
evaluates agents on SPEC-ENV over SPEC-CORPUS streams.

## 2. Conventions Common to All Documents

**Requirement levels.** The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
and only when, they appear in all capitals.

**Requirement identifiers.** Each normative statement carries a stable identifier
of the form `<DOC>-R-<nnn>` (for example `ENV-R-012`). Identifiers are never reused
or renumbered; a withdrawn requirement keeps its identifier and is marked
withdrawn. Code comments, tests, commits, and TODO items cite requirements by
identifier.

**Conformance notes.** A requirement MAY be followed by a note of the form
`Conformance: met | not met | partial | not applicable to legacy corpus`, with
the evidence (file and line at the commit named in the document header, or a test
node). A requirement without a note has not been checked.

**Test anchors.** Where a test pins a requirement, the note names it as
`[test: path::Class::test_name]`. Tests marked `xfail(strict=True)` pin a
requirement that is not yet met; removing the marker is part of the fix.

**Decision references.** `(D12)` cites a decision record in `decisions/`. A
requirement that depends on an open decision says so and states only what holds
under every option.

**Open issues.** Each document ends with numbered open issues that are not
register decisions (for example a figure awaiting confirmation). Open issues are
greppable as `OI-<DOC>-<n>`.

**Line references.** File and line references are to the commit named in each
document's header and are expected to drift; the requirement text, not the line
number, is authoritative.

**Style.** Formal register; no em dashes; quantitative claims name the database
they were measured on and the provenance note that records them.

## 3. Design Principles

These principles apply to all three documents and are the tie-breakers for open
decisions. Status: proposed; not yet endorsed by the author (OI-INDEX-2).

- **P1. Label-blindness of the observation.** No channel the agent conditions on
  may be a function of the ground truth (`is_malicious`, `attack_type`,
  `attack_stage`, `campaign_id`, or any attribution identifier). A feature that
  correlates with the label only because of how the corpus was constructed is a
  leak.
- **P2. Causality of actions.** An action graded as effective must have changed
  the defense state, and every change to the defense state must alter the future
  observation stream. An action that changes nothing scores zero.
- **P3. Temporal uniformity.** No observation or reward term encodes a special
  time. Warm-up, if any, belongs to the evaluation protocol.
- **P4. Determinism given a seed.** Composition and replay are reproducible from
  the corpus digest, the configuration, and one seed.
- **P5. Symmetry of construction.** Every structural property of the data
  (session assignment, address presence, process identity, source presence, line
  format) is produced by the same mechanism for benign and attack events.
- **P6. Separation of `info` from the observation.** Ground truth reaches the
  evaluation harness through `info` and never reaches the agent.

## 4. Purpose and Non-Goals

**Purpose.** A continual-learning control testbed reproducing a real server that
generates a continuous telemetry stream while under attack, serving as a Step 6 or
Step 8 domain of the Alberta Plan (Sutton, Bowling, and Pilarski, 2022): every
step is ordinary (temporal uniformity), the stream never terminates, the agent
learns from raw observation, action, and reward, and actions change what the
agent observes next. Status: proposed statement of the original intention;
awaiting confirmation (OI-INDEX-1).

**Terminology (settled 2026-08-19).** The environment is a trace-driven replay,
never a simulator: telemetry is recorded and replayed, and the only simulated
component is the defense layer. The loop is closed on observability and open on
adversary behavior. "Environment" is the software and its Gymnasium API; "corpus"
or "dataset" is released data; "benchmark" is the evaluation protocol together
with baseline results, never a single stream.

**Non-goals.** Adversary adaptation; synthetic generation of telemetry (a scripted
workload driving a real host is not synthetic telemetry, since the host produces
the logs and kernel events); live honeypot ingestion; network-layer capture
(NetFlow, `nftables`, `conntrack`; D19); multi-host defense. LSM enforcement
(ROADMAP Phase 13b) is outside this version (OI-INDEX-3).

## 5. Glossary

- **Attack instance**: one occurrence of a recording in a composed stream,
  identified by `instance_id` (D13; SPEC-CORPUS 6).
- **Attribution class**: the provenance assigned to an event at capture time:
  scenario stage, benign workload, or a class defined by D20.
- **Benchmark**: the evaluation protocol plus baseline results (SPEC-BENCH).
- **Control**: a defense-state change (block, throttle, isolate, and the
  process-level controls of D11) that suppresses future observations.
- **Corpus / dataset**: released data. The legacy corpus is v4.1; the corrected
  corpus is the D3 re-collection.
- **Effective action**: an action that changed the defense state (SPEC-ENV 7.4).
- **Environment**: the software and its Gymnasium API.
- **Ledger**: the recorder's append-only log of generator registrations
  (SPEC-CORPUS 6).
- **Recording**: one sealed, content-addressed capture of one scenario run on the
  reference target (SPEC-CORPUS 10).
- **Reference target**: the versioned, code-defined target host; Isildur is its
  first realization (SPEC-CORPUS 4).
- **Scenario package**: the self-contained unit in which an attack, and the benign
  driver for any service it adds, is contributed (SPEC-CORPUS 8).
- **Session**: a process subtree rooted at its session leader (kernel events) or
  the connection or client-host scope (log events), derived identically for both
  classes and never used for labeling (D1; SPEC-CORPUS 7).
- **Stream**: one composed sequence of events consumed by the environment.

## 6. Open Issues

- **OI-INDEX-1.** Confirm the purpose statement in Section 4. If the goal is
  narrower (a detection benchmark) or broader, D1, D2, and D10 resolve
  differently.
- **OI-INDEX-2.** Endorse, amend, or drop principles P1 to P6. P1 and P5 are what
  classify the address-presence artifact, the asymmetric sessions, and the
  `syslog` format split as defects rather than design choices.
- **OI-INDEX-3.** Confirm that NetFlow (ROADMAP Phase 8) and LSM enforcement
  (Phase 13b) are outside this specification version, or add a bounded
  future-scope note.
- **OI-INDEX-4.** The Exp 13 figure cited in CLAUDE.md, TODO.md, and ROADMAP.md
  (a 60% MAE reduction, Cohen's d = 2.577) is under review by the author. No
  document in this set cites it as current until the author confirms (D2).

## 7. References

- RFC 2119 and RFC 8174 (BCP 14): requirement-level key words.
- RFC 7322: RFC Style Guide (structural model, stripped of IETF boilerplate).
- Gymnasium API (Farama Foundation).
- Sutton, R. S., Bowling, M., and Pilarski, P. M. (2022). The Alberta Plan for AI
  Research. arXiv:2208.11173.
- Provenance notes in `data/provenance/`: `EBPF_IP_BYTE_ORDER_20260828.md`,
  `V4_ARCHIVE_STALENESS_20260726.md`, `V3_ARCHIVE_STALENESS_20260831.md`,
  `KERNEL_LABEL_AUDIT_20261107.md`, `BENIGN_COMPOSITION_AUDIT_20261108.md`.
