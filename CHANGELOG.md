# Changelog

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
