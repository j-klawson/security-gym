# Changelog

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
