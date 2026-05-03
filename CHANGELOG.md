# Changelog

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
