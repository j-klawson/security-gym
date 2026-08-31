# Byte-Reversed IPv4 Addresses on eBPF `connect` Events: Root Cause, Blast Radius, and Collector Fix

Date: 2026-08-28. Defect first recorded 2026-08-09 as Phase 14 defect 4. Collector fixed 2026-08-28; no published artifact is changed by that fix.

## 1. The Defect

Every `ebpf_network` `connect` event produced by `server/ebpf_collector.py` before 2026-08-28 carries an IPv4 destination address with its octets reversed. The Log4Shell container at `172.18.0.3` is recorded as `3.0.18.172`; the host `192.168.2.113` is recorded as `113.2.168.192`. The destination port on the same output line is correct, as are all addresses derived from log sources (`auth_log`, `web_access`, `web_error`), which never pass through the affected code path.

The corruption is present in two places per event: the `dst=` field of `raw_line`, and the `src_ip` column that `src/security_gym/parsers/ebpf.py:87-89` derives from it.

## 2. Root Cause

Three steps, of which the third is the error.

1. The BPF program copies the raw bytes of `sin_addr` into a `u32` (`server/ebpf_collector.py:148`):

   ```c
   bpf_probe_read_user(&evt.daddr, sizeof(evt.daddr), &sin->sin_addr);
   ```

   `sin_addr.s_addr` is stored in network byte order by definition. For `192.168.2.20` the four bytes in memory are `C0 A8 02 14`. This is a raw memory copy into an integer, so on little-endian x86-64 the resulting value is `0x1402A8C0`.

2. BCC decodes that struct field as a native `c_uint32`, so `event.daddr` reaches Python already in **host** byte order. The swap has happened implicitly and is not visible at the Python level.

3. `_ip_str` assumed the opposite:

   ```python
   def _ip_str(addr: int) -> str:
       """Convert a network-byte-order uint32 to dotted-quad string."""
       return ".".join(str(b) for b in struct.pack("!I", addr))
   ```

   `!I` serializes big-endian, producing `14 02 A8 C0`, printed as `20.2.168.192`. Two swaps in the same direction (memory to int, then int to memory) do not cancel. The docstring is where the mistake lives: the input is host-ordered, not network-ordered.

The destination port on the adjacent line was always correct because it uses the complementary idiom, packing native and unpacking big-endian, which applies exactly one swap:

```python
dport = struct.unpack("!H", struct.pack("H", event.dport))[0]
```

## 3. Why It Survived Spot-Checking

Addresses that are palindromic under octet reversal are invariant and appear correct. In every artifact the unaffected remainder is almost entirely `0.0.0.0`, with a small contribution from `8.8.8.8`. In `exp_7d_brute_v4.db`, for example, 27,777 of 85,383 addressed events are unaffected and 27,771 of those are `0.0.0.0`. Any spot-check that happened to land on those rows reported a correct address.

## 4. Blast Radius

Full-table scans of the live databases in `data/`, counting `ebpf_network` events with a non-NULL `src_ip` and classifying each distinct address as reversed (not invariant under octet reversal) or not.

| Artifact | Addressed `ebpf_network` events | Byte-reversed | Share | Distinct addresses | Distinct reversed |
|---|---:|---:|---:|---:|---:|
| `campaigns_v2.db` | 603 | 430 | 71.31% | 8 | 6 |
| `benign_v4.db` | 57,217 | 38,584 | 67.43% | 115 | 113 |
| `exp_7d_brute_v4.db` | 85,383 | 57,606 | 67.47% | 106 | 104 |
| `exp_30d_heavy_v4.db` | 374,261 | 254,635 | 68.04% | 114 | 112 |
| `exp_90d_v4.db` | 1,103,556 | 744,678 | 67.48% | 114 | 112 |
| `exp_365d_realistic_v4.db` | 4,455,358 | 3,001,442 | 67.37% | 114 | 112 |

Every one of these artifacts is published, on Zenodo under the v4.1 record (DOI 10.5281/zenodo.21763493) and, for the three smaller streams, on the HuggingFace mirror `j-klawson/security-gym-v4`. The counts above are for addressed events only; `accept` events carry no address at all under Phase 14 defect 5 and are therefore outside this table.

Most frequent reversed values, consistent across all artifacts: `26.2.168.192` (`192.168.2.26`), `104.2.168.192` (`192.168.2.104`), `1.2.168.192` (`192.168.2.1`, the gateway), and in the campaign corpus `3.0.18.172` (`172.18.0.3`, the Log4Shell container, 350 events, matching the 350 Log4Shell requests).

## 5. Consequences

1. **Split host identity across channels.** The same machine appears as `192.168.2.113` in `auth_log` and as `113.2.168.192` in `ebpf_network`. Any analysis that joins the log and kernel channels on IP silently fails to match.

2. **IP-keyed defense is incoherent in the environment.** `_apply_action` (`src/security_gym/envs/log_stream_env.py:433-451`) stores `row["src_ip"]` in the blocklist verbatim, with no parsing or normalization, and `_advance` matches by string equality. A block issued on an address seen in auth.log therefore cannot suppress that host's network eBPF events, and vice versa. Per-IP containment measured across channels is wrong by construction. This bears directly on the control-benchmark work in ROADMAP Phase 15.

3. **Labeling is unaffected in outcome.** `CampaignLabeler` matches on time window plus attacker IP. Attacker `connect` events cannot match on IP, so they fall back to the time window, which is the same path all malicious `ebpf_network` events already take under defect 5. The `is_malicious` labels are not wrong; the attribution basis is weaker than the schema implies.

4. **No published result is invalidated by this defect alone.** Log-only results (session F1 0.979) never touch these addresses. The eBPF ablation (Exp 13) is already under review for the reasons in Phase 14 defects 1 to 3; this adds to that review rather than constituting a separate retraction.

## 6. The Fix

`_ip_str` now packs native:

```python
return ".".join(str(b) for b in struct.pack("=I", addr))
```

`"="` is correct on either host endianness: on a little-endian host it reproduces the original network-order byte sequence, and on a big-endian host the raw copy leaves the value in network order, which is also native order there. Verified against `socket.inet_ntoa(struct.pack("=I", addr))`.

Regression tests are in `tests/test_ebpf_collector.py`, covering five non-palindromic addresses including `172.18.0.3`, plus the palindromic cases that masked the defect. To make the helper importable on a host without BCC, the `ImportError` now sets `BPF = None` and is reported by `main()` rather than calling `sys.exit(1)` at import time; the daemon's behaviour and exit status are unchanged.

The fix applies to future collections only. It does not alter any existing database, and the corrected collector has not yet been redeployed to Isildur or the three baseline hosts (Phase 14 checklist).

## 7. Reading the Published Data

Reverse the octets:

```python
def unreverse(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))

unreverse("3.0.18.172")     # -> "172.18.0.3"
unreverse("113.2.168.192")  # -> "192.168.2.113"
```

The transformation is lossless and self-inverse, so a reversal pass over the `raw_line` and `src_ip` fields of `ebpf_network` `connect` rows would fully correct this defect in the existing corpus. It would not touch `accept` events, which have no address to correct, so a corpus repaired this way is still partially defective and must be disclosed as such.

## 8. Disposition (open)

Three options, tracked in TODO.md under Phase 14:

- **Document only.** Done as of this report: `CLAUDE.md`, `ROADMAP.md`, `TODO.md`, `data/DATASET_README.md`, and the HuggingFace card all now carry the discrepancy and the reversal rule. Consumers who read the documentation can correct the data; consumers who do not, cannot.
- **Reversal pass over the shipped databases.** Mechanical and lossless for `connect` events, but produces a new dataset version and leaves defect 5 uncorrected.
- **Re-collection.** The only path that fixes defects 4 and 5 together, and the one already under consideration for defects 1 to 3.

Not yet decided: whether the published Zenodo 4.1 record warrants an erratum rather than repo-side documentation alone. Downloaders of the archives have no in-band signal that the addresses are reversed. This is coupled to the downstream-consumer audit still open under "V4 Published-Archive Remediation".
