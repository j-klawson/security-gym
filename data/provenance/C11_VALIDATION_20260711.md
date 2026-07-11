# C11 Validation: Provenance of the Rule-Based Baseline Table

Date: 2026-07-11.
Scope: RLC 2026 camera-ready item C11 (`../research-assistant/papers/security-gym/rlc/REVIEW_RESPONSE_TODO.md`), which records that no stored artifact backed the rule-based baseline table and that three conflicting captions existed in the written record. This report reconstructs the provenance of both number sets from evidence recovered on the machine that ran the original experiments. No benchmark was re-run for this validation.

## 1. The Two Number Sets

Set A (security-gym `README.md` "Baselines" section and `data/DATASET_README.md`; also paper drafts v2 through v7):

| Agent | Precision | Recall | F1 | Mean Reward |
|-------|----------:|-------:|---:|------------:|
| pass-only | 0.000 | 0.000 | 0.000 | -0.073 |
| random | 0.003 | 0.665 | 0.005 | -3.985 |
| threshold(5) | 1.000 | 0.005 | 0.011 | -0.084 |
| keyword | 0.987 | 0.013 | 0.025 | -0.073 |

Set B (RLC camera-ready `rlc/main.tex` Table 1, `\label{tab:baselines}`; also `drafts/v8.md`, `drafts/v7-rlc.md`, `drafts/v8-rlc.md`):

| Agent | Precision | Recall | F1 |
|-------|----------:|-------:|---:|
| pass-only | 0.000 | 0.000 | 0.000 |
| random | 0.004 | 0.665 | 0.007 |
| threshold(5) | 1.000 | 0.000 | 0.000 |
| keyword | 0.982 | 0.009 | 0.018 |

## 2. Evidence Inventory

| # | Evidence | Location | Date | Bears on |
|---|----------|----------|------|----------|
| E1 | Recovered stdout of a full-stream benchmark run | `~/repos/research/rlsecd/logs/benchmark_ruleagents_v4_30d.log` (mtime 2026-05-28 12:00:47 EDT; SHA256 `6766545e...40a9a62`); verbatim copy committed as `rlsecd-log-20260528_benchmark_30d_v4_fullstream.txt` in this directory | 2026-05-28 | Set B |
| E2 | Bytecode cache write for `examples/` agent modules | `examples/__pycache__/{keyword,random,threshold}_agent.cpython-313.pyc`, all mtime 2026-05-28 08:27:55 EDT | 2026-05-28 | Set B run start time |
| E3 | security-gym commit `f4ba8c0` "docs: fill in real baseline metrics from v4 benchmark runs"; message states "30d heavy stream (1M steps, all 5 attack types)" and lists the pass-only, random, and threshold(5) values of Set A verbatim | this repository | 2026-04-02 08:14 EDT | Set A |
| E4 | security-gym commit `84cc3a6` "feat: add multi-channel keyword heuristic agent baseline"; message states "Results on exp_30d_heavy_v4.db (1M steps): precision=0.987, recall=0.013, F1=0.025" | this repository | 2026-04-03 08:58 EDT | Set A |
| E5 | research-assistant commit `5a46cd1` adds `drafts/v2.md` captioned "the `exp_30d_heavy_v4` stream (21.5M events, 1M steps sampled)"; drafts v3 through v6 retain this caption | `../research-assistant` | 2026-04-10 | Set A caption history |
| E6 | research-assistant commit `259bd9c` (v7 draft) re-captions the same numbers as "the `exp_30d_heavy.db` v3 stream (~1M session-level events after filtering to SSH-session-relevant activity)" while noting "v4 reruns under the §6.1 canonical protocol are in progress" | `../research-assistant` | 2026-05-04 | Set A mis-caption |
| E7 | research-assistant commits `b5746e8` (v8 draft, 20:04) and `b8df92f` (RLC submission, 20:29) introduce Set B captioned as the full v4 stream | `../research-assistant` | 2026-05-28 | Set B first publication |
| E8 | Negative searches: no `benchmark.py` invocation in `~/.bash_history`; no benchmark stdout in any surviving Claude Code transcript under `~/.claude/projects/` (oldest surviving transcripts postdate both runs); no April-dated output file anywhere under `~/repos/research` | machine-wide | 2026-07-11 | Set A artifact absence |

## 3. Answers

### Q1. What command produced each set, and when

Set B (answered with a recovered artifact, E1 and E2). The run executed
`examples/benchmark.py` on `data/exp_30d_heavy_v4.db` with no `--max-steps`
(the log contains no "Max steps:" line and the pass-only agent ran 21,511,208
steps, the full stream) and no recoverable `--seed` (the argparse default is
42). The interpreter was `~/repos/research/rlsecd/.venv/bin/python` (the
`UserWarning` in the log names that venv path), the working directory was this
repository (the DB path is relative), and stdout was redirected to
`~/repos/research/rlsecd/logs/benchmark_ruleagents_v4_30d.log`. The run
started at 08:27:55 EDT on 2026-05-28 (E2, first-import bytecode write) and
finished at 12:00:47 EDT (log mtime). The per-agent elapsed times printed in
the log sum to 12,772.1 s (3 h 32 m 52 s), which matches that window exactly.
Rounding each recovered value to three decimals reproduces Set B
digit-for-digit:

| Agent | Log P | Log R | Log F1 | Set B P/R/F1 |
|-------|------:|------:|-------:|:-------------|
| pass-only | 0.0000 | 0.0000 | 0.0000 | 0.000 / 0.000 / 0.000 |
| random | 0.0036 | 0.6652 | 0.0072 | 0.004 / 0.665 / 0.007 |
| threshold(t=5,w=300) | 1.0000 | 0.0001 | 0.0002 | 1.000 / 0.000 / 0.000 |
| keyword(a=2.0,b=5.0) | 0.9816 | 0.0092 | 0.0183 | 0.982 / 0.009 / 0.018 |

Set A (answered from contemporaneous commit messages only; no stdout artifact
survives, E8). Two runs of `examples/benchmark.py data/exp_30d_heavy_v4.db
--max-steps 1000000` (seed at the default of 42, not independently
verifiable): one on or immediately before 2026-04-02 08:14 EDT producing the
pass-only, random, and threshold rows (E3; at that commit the script swept
thresholds 3, 5, and 10, and the t=5 row was taken), and one on or immediately
before 2026-04-03 08:58 EDT producing the keyword row after that agent was
written (E4). Both commit messages state the database (`exp_30d_heavy_v4.db`)
and the step count (1M) explicitly.

### Q2. Which caption is wrong

The v7 draft caption is wrong; the other two are correct.

- README ("`exp_30d_heavy_v4.db` (1M steps)"): correct. It matches both
  contemporaneous commit messages (E3, E4).
- Old drafts: the C11 premise that drafts v2 through v7 captioned Set A as the
  v3 stream is itself inaccurate. Drafts v2 through v6 caption the table
  correctly as "`exp_30d_heavy_v4` stream (21.5M events, 1M steps sampled)"
  (E5). The mis-caption enters only at v7 (2026-05-04, E6), which relabels the
  identical numbers as "the `exp_30d_heavy.db` v3 stream (~1M session-level
  events after filtering to SSH-session-relevant activity)". Both clauses of
  that caption are unsupported: the numbers came from the v4 stream, and the
  1M figure was a `--max-steps` cap, not a filtering step. The v7 sentence
  appears to be a post-hoc rationalization introduced while the v4 full-stream
  rerun was still pending, and it was submitted to NeurIPS in that form.
- Camera-ready ("full v4 30-day stream, 21.5M events"): correct, now verified
  digit-for-digit against the recovered artifact (E1). One wording caveat: the
  caption sentence in Section 5 says the five agents are evaluated at "30
  seeds"; the 30-seed protocol applies to the learned Baseline-12 agent,
  whereas the four rule-based rows come from this single deterministic run
  (only the random agent is seed-sensitive, at the default seed of 42).

### Q3. Is there a recoverable output artifact for Set B

Yes. The full stdout of the 2026-05-28 run survived at
`~/repos/research/rlsecd/logs/benchmark_ruleagents_v4_30d.log` (it was written
into the rlsecd repository because the run borrowed that project's virtual
environment, and rlsecd's `logs/` directory is not tracked by git, which is
why repository searches missed it). A verbatim copy with a provenance header
is committed alongside this report as
`rlsecd-log-20260528_benchmark_30d_v4_fullstream.txt`. The full-stream re-run
contemplated by item C11 is therefore not required to back Table 1. No
artifact survives for Set A; if the README table is ever to be regenerated
rather than re-captioned, a 1M-step re-run would be needed, but nothing in the
camera-ready depends on Set A.

## 4. Validation Analysis

### 4.1 Internal consistency (F1 = 2PR / (P + R))

Recovered log (four printed decimals): random 2(0.0036)(0.6652)/(0.6688) =
0.0072 and threshold 2(1.0)(0.0001)/(1.0001) = 0.0002 reproduce the printed F1
exactly. The keyword row computes to 0.0182 from the printed four-decimal P
and R against a printed F1 of 0.0183; this is expected rounding interaction
(true values within the printed rounding intervals, for example P = 0.98164,
R = 0.00925, yield F1 that rounds to 0.0183). No row is inconsistent.

Set A and Set B (three printed decimals): every row of both sets admits true
(P, R) values within the rounding interval of the printed values whose F1
rounds to the printed F1. Two Set A rows are consistent only near an edge of
their rounding intervals (random: F1 of the printed values is 0.0060 against a
printed 0.005, requiring true P near 0.0025 to 0.0028; threshold: 0.0100
against a printed 0.011, requiring true R near 0.0053 to 0.0055). This is
compatible with correct rounding of an unrecovered raw table and is flagged
for completeness, not as an error.

### 4.2 Timeline

1. 2026-03-22: `exp_30d_heavy_v4.db` composed (file mtime).
2. 2026-04-02/03: two 1M-step benchmark runs on the v4 stream produce Set A;
   README and DATASET_README updated with the correct v4/1M caption (E3, E4).
3. 2026-04-10: draft v2 copies Set A with the correct caption; v3 through v6
   inherit it (E5).
4. 2026-05-04: draft v7 re-captions Set A as the v3 stream with a filtering
   rationale; the v4 full-stream rerun is noted as in progress (E6).
5. 2026-05-28, 08:27:55 to 12:00:47 EDT: the full-stream v4 run executes and
   produces Set B (E1, E2).
6. 2026-05-28 evening: draft v8 (20:04) and the RLC submission (20:29) publish
   Set B with the correct full-stream caption (E7); the camera-ready inherits
   it unchanged.

The two sets therefore reflect two genuine runs of the same script on the same
database at different step counts and different code states (the April runs
predate the 0.4.x environment renames; the May run used security-gym 0.4.3 era
code and the post-`84cc3a6` single-threshold benchmark script). The identical
random recall (0.665) across both sets is a coincidence of rounding: the
recovered full-stream value is 0.6652, and the 1M-step value rounded to the
same three decimals.

### 4.3 Notes on the recovered log

The step counts differ per agent (random 19,971,741; threshold 21,123,665;
keyword 21,502,107 against a full stream of 21,511,208) because agents that
block source IPs suppress subsequent events from those IPs; this is
environment semantics, not truncation. The single `UserWarning` from
gymnasium's passive environment checker is cosmetic and does not affect
metrics.

## 5. Authoritative Table Rows

From the recovered artifact (E1), rounded to three decimals; these match the
camera-ready Table 1 exactly, so no numeric change to `main.tex` is required.

Markdown:

| Agent | Basis | Precision | Recall | F1 |
|-------|-------|----------:|-------:|---:|
| pass-only | per-event | 0.000 | 0.000 | 0.000 |
| random | per-event | 0.004 | 0.665 | 0.007 |
| threshold(5) | per-event | 1.000 | 0.000 | 0.000 |
| keyword | per-event | 0.982 | 0.009 | 0.018 |

LaTeX (rows for `tab:baselines`):

```latex
pass-only                & per-event & 0.000 & 0.000 & 0.000 \\
random                   & per-event & 0.004 & 0.665 & 0.007 \\
threshold(5)             & per-event & 1.000 & 0.000 & 0.000 \\
keyword                  & per-event & 0.982 & 0.009 & 0.018 \\
```

## 6. Recommended Follow-Up (outside the scope of this validation)

These edits belong to the paper and README repositories and are deliberately
not applied here:

1. `rlc/main.tex` Section 5: qualify the "30 seeds" phrasing so it applies to
   Baseline-12 only, and optionally cite the committed provenance artifact.
2. README and `data/DATASET_README.md`: either keep Set A with its correct
   v4/1M-step caption or replace it with the full-stream Set B numbers from
   the recovered artifact for consistency with the paper.
3. `REVIEW_RESPONSE_TODO.md` item C11 and `T1_METRIC_DEFINITIONS_DRAFT.md`
   open item 1: mark resolved by recovered artifact; correct the premise that
   drafts v2 through v7 all carried the v3 caption (v2 through v6 were
   correct; only v7 mis-captioned).
