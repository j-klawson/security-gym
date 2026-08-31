# Changelog

## 0.6.0

### Added a state space: the `defense_state` observation channel

The observation reported the host's telemetry and nothing about the agent's own controls. `blocked_ips`, `throttled_ips`, `is_isolated`, and `events_dropped` were reachable only through the `info` dict, which also carries the ground-truth labels, so an agent had no observable record of what it had already done and reading it sat adjacent to the label channel. An operator in that position runs `fail2ban-client status` or `iptables -L`. The new channel reports blocked and throttled address lists, isolation, suppressed-event count, event-seconds since the state last changed, and whether the source of the current event is already under a control. Text mode renders command-style status output; hybrid mode encodes `Box(6)`. Every field is a consequence of the agent's own actions, so the channel leaks no ground truth. On by default (`defense_state_obs=True`); pass `False` for the previous observation space.

### Added target selection: naming an address instead of acting on the current event

Every stateful action bound to the current event's `src_ip`, so `block_source` meant "block the source of this event" and never "block address X". That forecloses most of the stream: 93.50% of `exp_30d_heavy_v4` events carry no source address, 99.9% of those are eBPF, and `ebpf_file` alone accounts for 94.6% of them. This is structural rather than a parsing gap, since an `openat` or `execve` has no peer address to record. An agent that inferred compromise from a suspicious `execve` therefore could not act on it, and a blocked host could never be released, because its events stop arriving and no later step could name it.

The action gains a `target` component: 0 is the current event's source, and 1..N name a slot in the target slate, an observable list of addresses seen anywhere in the stream. Slots are stable so a learned index keeps its referent; eviction is least-recently-seen among addresses not under a control, and blocked or throttled addresses are pinned, which is what makes release reachable under the default `"drop"` visibility. The slate ships as its own observation channel, since an index into an unobservable list is not learnable, and the hybrid encoding hashes addresses with the same `SEED_IP` as the network channel's `dst_ip_hash` so a slate slot and a kernel event agree on a host. Default `target_slate_size=64`, sized from the corpus: 200 to 400 distinct addresses are live per 5,000-addressed-event window. Pass `0` for the previous action space.

### Reward now reflects effect

An address-taking action that changed no state scored the full action reward, so a block that dropped nothing was paid +1.0 on a malicious event or -1.0 on a benign one. On these streams that was the common case rather than the corner case. Such actions now score 0.0. Separately, an explicitly targeted action is graded on the target address's last observed label rather than on whatever event is on screen, which is what makes it coherent to block a host named from kernel evidence while looking at an unrelated event; the grading is causal, using only labels the agent has already been shown.

### Fixed byte-reversed IPv4 addresses in the eBPF collector

`_ip_str` packed a host-byte-order value as network byte order, reversing the octets on every `connect` event: the Log4Shell container at `172.18.0.3` was recorded as `3.0.18.172`. `bpf_probe_read_user` copies the raw network-order bytes of `sin_addr` into a `u32` and BCC decodes that field natively, so the value arrives already host-ordered and packing it `"!I"` swapped a second time. Now packs `"=I"`, correct on either host endianness. The destination port on the same line was always correct, since it uses the complementary pack-native/unpack-big-endian idiom. **This fix applies to future collections only; every published artifact still carries reversed addresses**, quantified per artifact in `data/provenance/EBPF_IP_BYTE_ORDER_20260828.md`. To make the helper testable off a collection host, the BCC `ImportError` now sets `BPF = None` and is reported by `main()` instead of exiting at import time; the daemon's behaviour is unchanged.

### Fixed the `Text` observation charset

Every text channel joins its ring buffer with `"\n"`, but the declared charset was printable ASCII only, so `observation_space.contains(obs)` was false for any multi-line channel and Gymnasium's passive checker warned on it. Newline is now in the charset.

### Regenerated the baseline table

The README baselines were generated while `include_risk_reward` still defaulted to `True` and were not regenerated when commit `a5ceae9` flipped that default off, so the mean-reward column described a reward function the environment no longer computed. The published pass-only figure of -0.073 is reproduced exactly (-0.0733) by adding the dormant risk-MSE term back to the current -0.0120. The table now reports the 0.6.0 defaults. Detection metrics were unaffected, since they never depended on the reward.

### Note on the published contract

`rlc2026-camera-ready` pins the repository state described by the RLC 2026 Continual RL Workshop camera-ready. That workshop is non-archival with no proceedings, so these contract changes supersede rather than invalidate a published artifact. Every changed default can be reconstructed with constructor arguments.


### Pinned the ruff rule set against upstream default drift

The `lint` CI job began failing on unchanged source after ruff 0.16 widened its implicit default rule selection beyond `E4`/`E7`/`E9`/`F` to include `I`, `UP`, and subsets of `RUF`, `BLE`, `SIM`, `PERF`, `FURB`, and `S`. Because `pyproject.toml` declared no `select` and the `[dev]` extra pinned only `ruff>=0.4.0`, a routine tooling upgrade silently changed what CI enforced, producing 188 errors across code that had not been touched. The enforced rule set is now declared explicitly (`[tool.ruff.lint] select = ["E4", "E7", "E9", "F"]`) and the dev pin is bounded to `ruff>=0.16.1,<0.17`, so the rules stay stable across ruff releases and new families are adopted deliberately. No library code changed.

## 0.5.1

### Scoped the CI dependency audit to the project closure

The `security` CI job's `pip-audit` step audited the entire job environment, which includes the audit tooling itself (pip, and pip-audit's own `requests`/`urllib3`/`idna`/`pygments` transitive dependencies). Newly disclosed advisories in that tooling (none in security-gym's runtime dependencies: `gymnasium`, `numpy`, `mmh3`, `pyyaml`) were failing CI even though they are not shipped by the package. The step now resolves the project's `[dev]` dependency closure in a clean virtual environment and audits that requirements set, so the audit reflects what security-gym actually ships. The `[dev]` pin for `pytest` is raised to `>=9.0.3` to clear CVE-2025-71176 (which also pulls the fixed `pygments` 2.20.0). No library code changed.

## 0.5.0

### Added opt-in block recovery: `block_visibility` and `block_ttl`

The defensive action set exposes `block_source` and `unblock`, but the agent could not learn the block then unblock loop. Once an IP was blocked, `_advance` dropped 100% of its events, so the IP never reappeared as an observation; and `unblock` only targets the current event's `src_ip`. Blocking an IP therefore made it permanently unobservable for the rest of the episode, so an `unblock` directed at it was unreachable. Two opt-in, default-off, composable constructor parameters on `SecurityLogStreamEnv` (and `SecurityLogStreamHybridEnv`) restore observability and recoverability.

`block_visibility` accepts `"drop"` (default) or `"deny_log"`. Under `"deny_log"`, a blocked IP's events are still dropped by the firewall (the events do not reach the server and the consequence reward still fires), but each one is surfaced in the observation as a ground-truth-blind firewall deny-log line prefixed `"[FIREWALL DENY] "`. A wrongly-blocked benign IP keeps producing events, which now surface as denied entries, giving the agent repeated steps where that IP is the current event so an explicit `unblock` becomes reachable and meaningful. A correctly-blocked attacker that goes quiet produces no events and costs nothing to leave blocked. The deny rendering is a pure function of agent-observable fields (a static prefix plus the original raw line) and never references `is_malicious`, `attack_type`, or `attack_stage`, so the surfaced observation leaks no label.

`block_ttl` (event-time seconds, `None` by default for permanent blocks) auto-expires a block fail2ban-style: once `block_ttl` seconds of event-time elapse since the ban started, the IP is removed from the blocklist and its next event re-surfaces for a fresh decision. The two parameters compose; TTL expiry is evaluated first, then drop-or-surface per `block_visibility`.

### Reward and step accounting under `deny_log`

When the current observation is a surfaced deny-log entry, the firewall, not the agent's live decision, is acting on that event. The per-step action reward and risk term are zeroed and the event contributes only the consequence term (`+malicious_drop_reward` / `-benign_drop_penalty`), avoiding double-counting a single event under both the consequence and action terms. The agent's action on a denied event (for example `unblock`) is graded on the next live event it produces. Episode-total consequence reward is identical to `"drop"` mode; `"deny_log"` only redistributes it across steps (one step per blocked event rather than accumulating into one) and increases episode length accordingly.

### Scope and limitations

`block_visibility` governs only the 100%-block path; isolation and throttle are unchanged. In the Hybrid env, the structured eBPF channels carry no deny-log marker (no `raw_line`, no spare column), so a denied eBPF event is reward-correct but observationally indistinguishable in the structured array; the deny annotation is visible only in the text channels, where most blockable entities (auth and network events) are surfaced. The default configuration (`block_visibility="drop"`, `block_ttl=None`) reproduces the prior permanent-block semantics byte-for-byte, verified by a dedicated regression test.

## 0.4.2

### Added HuggingFace dataset mirror and Croissant metadata

The v4 dataset is now mirrored at [`huggingface.co/datasets/j-klawson/security-gym-v4`](https://huggingface.co/datasets/j-klawson/security-gym-v4) for low-friction reviewer access. The mirror hosts the three smaller composed streams (7d/30d/90d, totaling 188 MB compressed); the full release including the 365-day stream and the underlying base databases remains on Zenodo only due to size.

A MLCommons Croissant 1.0 metadata file with Responsible AI fields is committed at `data/croissant.json` and uploaded to the root of the HuggingFace dataset. It documents the schema, distributions across both mirrors, citation, and the RAI block (data collection, annotation protocol, preprocessing, biases, limitations, intended/not-intended use, social impact, PII handling). Validates via `mlcroissant`.

### Fixed Zenodo dataset concept DOI in `data/DATASET_README.md` and `README.md`

The Zenodo dataset concept DOI is `10.5281/zenodo.18901541`, retrieved from the Zenodo JSON API `conceptdoi` field on the v4 record. The previously-cited `10.5281/zenodo.18901627` was actually the security-gym software v0.3.3 record, not a dataset concept. Documentation now uses the correct DOI; the software Zenodo DOI badge in `README.md` is removed (PyPI is the durable software identifier; the Zenodo software deposit was carrying maintenance cost without serving readers).

### Trimmed software Zenodo citation from BibTeX block in `data/DATASET_README.md`

The `@software{...}` BibTeX entry in the dataset README no longer pins a `version` or `doi` to the Zenodo software deposit; reproducibility for the software is now anchored on PyPI version pins (`pip install security-gym==0.4.2`).

## 0.4.1

### Removed deprecation aliases

The `SecurityLogStream-v1` and `SecurityLogStream-v2` aliases registered in 0.4.0 are removed. Use `SecurityLogStream-Text-v0` and `SecurityLogStream-Hybrid-v0` instead. The deprecation window was closed early because the only known consumers (`rlsecd`, `chronos-sec`) are coordinated repos under the same maintainer; carrying the aliases for an extended window provided no real protection.

### Renamed internal class and module

The Hybrid-mode env class and module are renamed to match the registered ID:

- `SecurityLogStreamEnvV2` → `SecurityLogStreamHybridEnv`
- `security_gym.envs.log_stream_env_v2` → `security_gym.envs.log_stream_env_hybrid`

The corresponding test module is renamed to `tests/test_env_hybrid.py`.

## 0.4.0

### Renamed environment IDs

The two registered Gymnasium environments are renamed to make the observation-mode distinction explicit and to stop overloading the `-vN` suffix as a feature-set version counter.

| Old ID                  | New ID                          | Mode    |
| ----------------------- | ------------------------------- | ------- |
| `SecurityLogStream-v1`  | `SecurityLogStream-Text-v0`     | Text    |
| `SecurityLogStream-v2`  | `SecurityLogStream-Hybrid-v0`   | Hybrid  |

The two modes are otherwise identical in action space, reward structure, defense state, and continuous-stream semantics; they differ only in how the eBPF channels are encoded (raw text vs fixed-width float32 arrays). The Gymnasium `-v0` suffix tracks API stability per mode and bumps independently if a mode's channel contract changes.

### Backward compatibility

`SecurityLogStream-v1` and `SecurityLogStream-v2` remain registered as deprecated aliases through the 0.4.x line. Calling `gymnasium.make()` with either old ID resolves to the corresponding new env and emits a `DeprecationWarning` recommending the new ID. Both aliases are scheduled for removal in 0.5.0.

### Migration

Replace `gym.make("SecurityLogStream-v1", ...)` with `gym.make("SecurityLogStream-Text-v0", ...)` and `gym.make("SecurityLogStream-v2", ...)` with `gym.make("SecurityLogStream-Hybrid-v0", ...)`.

No changes are required to observation handling, action handling, or reward consumption.
