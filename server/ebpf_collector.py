#!/usr/bin/env python3
"""eBPF kernel event collector daemon for security-gym.

Attaches to kernel tracepoints via BCC to capture process execution,
network connections, and file access events. Outputs timestamped text
lines suitable for ingestion by the security-gym EventStore.

Requires root/CAP_BPF and BCC (python3-bpfcc) on the target host.

Usage:
    sudo python3 ebpf_collector.py --output /tmp/security_gym_events.log
    sudo python3 ebpf_collector.py --duration 60  # collect for 60 seconds
"""

from __future__ import annotations

import argparse
import os
import signal
import struct
import sys
import time
from ctypes import c_char, c_int, c_uint, c_uint16, c_uint32, c_ulonglong
from datetime import datetime, timezone

try:
    from bcc import BPF  # type: ignore[import-not-found]
except ImportError:
    print("ERROR: BCC not installed. Run: sudo apt install bpfcc-tools python3-bpfcc",
          file=sys.stderr)
    sys.exit(1)


# ── BPF C programs ───────────────────────────────────────────────────

# Shared map for self-PID filtering
_SELF_FILTER = """
BPF_HASH(self_pids, u32, u8);

static inline int is_self(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return self_pids.lookup(&pid) != NULL;
}
"""

# Process events: execve + exit
BPF_PROCESS = _SELF_FILTER + r"""
#include <linux/sched.h>

struct execve_event_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[64];
    char parent_comm[64];
    char args[256];
};

struct exit_event_t {
    u64 ts;
    u32 pid;
    int code;
};

BPF_PERF_OUTPUT(execve_events);
BPF_PERF_OUTPUT(exit_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (is_self()) return 0;

    struct execve_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /* Read parent PID and comm from task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid),
                          &task->real_parent->tgid);
    bpf_probe_read_kernel_str(&evt.parent_comm, sizeof(evt.parent_comm),
                              &task->real_parent->comm);

    /* Read first arg (filename) */
    const char *filename = args->filename;
    bpf_probe_read_user_str(&evt.args, sizeof(evt.args), filename);

    execve_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    if (is_self()) return 0;

    struct exit_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    /* Exit code lives in task_struct; read via bpf_probe_read_kernel */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int exit_code = 0;
    bpf_probe_read_kernel(&exit_code, sizeof(exit_code),
                          &task->exit_code);
    evt.code = exit_code >> 8;

    exit_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

# Network events: connect + accept
BPF_NETWORK = _SELF_FILTER + r"""
#include <linux/socket.h>
#include <linux/in.h>

struct connect_event_t {
    u64 ts;
    u32 pid;
    u32 uid;
    char comm[64];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
};

BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(accept_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (is_self()) return 0;

    struct connect_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    evt.family = family;

    if (family == 2) {  /* AF_INET */
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&evt.daddr, sizeof(evt.daddr), &sin->sin_addr);
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &sin->sin_port);
    }

    connect_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    if (is_self()) return 0;

    struct connect_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    accept_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

# File events: openat + unlinkat
BPF_FILE = _SELF_FILTER + r"""
struct file_event_t {
    u64 ts;
    u32 pid;
    char comm[64];
    char path[256];
    int flags;
    u8 is_unlink;
};

BPF_PERF_OUTPUT(file_events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (is_self()) return 0;

    struct file_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    const char *fname = args->filename;
    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), fname);
    evt.flags = args->flags;
    evt.is_unlink = 0;

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    if (is_self()) return 0;

    struct file_event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    const char *fname = args->pathname;
    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), fname);
    evt.is_unlink = 1;

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""


# ── Event formatting ─────────────────────────────────────────────────

def _now_iso() -> str:
    """Current UTC time in RFC 3339 format with microseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ip_str(addr: int) -> str:
    """Convert a network-byte-order uint32 to dotted-quad string."""
    return ".".join(str(b) for b in struct.pack("!I", addr))


def _decode_flags(flags: int) -> str:
    """Decode open() flags to human-readable string."""
    flag_map = {
        0o0: "O_RDONLY",
        0o1: "O_WRONLY",
        0o2: "O_RDWR",
        0o100: "O_CREAT",
        0o200: "O_EXCL",
        0o1000: "O_TRUNC",
        0o2000: "O_APPEND",
    }
    parts = []
    access = flags & 0o3
    if access in flag_map:
        parts.append(flag_map[access])
    for bit, name in flag_map.items():
        if bit > 0o2 and flags & bit:
            parts.append(name)
    return "|".join(parts) if parts else str(flags)


class EbpfCollector:
    """eBPF event collector — attaches to kernel tracepoints and writes events."""

    def __init__(self, output_path: str = "/tmp/security_gym_events.log"):
        self.output_path = output_path
        self._running = False
        self._bpf_instances: list = []
        self._output_file = None

    def _populate_self_pids(self, b) -> None:
        """Add our PID and children to the self-filter BPF map."""
        pid_map = b["self_pids"]
        my_pid = os.getpid()
        pid_map[c_uint(my_pid)] = c_char(1)
        # Also add parent (in case we're launched from a script)
        ppid = os.getppid()
        pid_map[c_uint(ppid)] = c_char(1)

    def _write_line(self, line: str) -> None:
        """Write a formatted event line to the output file."""
        if self._output_file:
            self._output_file.write(line + "\n")
            self._output_file.flush()

    # ── Perf event callbacks ─────────────────────────────────────────

    def _on_execve(self, cpu, data, size):
        event = self._bpf_process["execve_events"].event(data)
        comm = event.comm.decode("utf-8", errors="replace")
        parent_comm = event.parent_comm.decode("utf-8", errors="replace")
        args = event.args.decode("utf-8", errors="replace")
        self._write_line(
            f"{_now_iso()} execve pid={event.pid} ppid={event.ppid} "
            f"uid={event.uid} comm={comm} parent_comm={parent_comm} "
            f"args={args}"
        )

    def _on_exit(self, cpu, data, size):
        event = self._bpf_process["exit_events"].event(data)
        self._write_line(
            f"{_now_iso()} exit pid={event.pid} code={event.code}"
        )

    def _on_connect(self, cpu, data, size):
        event = self._bpf_network["connect_events"].event(data)
        if event.family != 2:  # Only log AF_INET
            return
        comm = event.comm.decode("utf-8", errors="replace")
        dst = _ip_str(event.daddr)
        dport = struct.unpack("!H", struct.pack("H", event.dport))[0]
        self._write_line(
            f"{_now_iso()} connect pid={event.pid} uid={event.uid} "
            f"comm={comm} dst={dst}:{dport}"
        )

    def _on_accept(self, cpu, data, size):
        event = self._bpf_network["accept_events"].event(data)
        comm = event.comm.decode("utf-8", errors="replace")
        self._write_line(
            f"{_now_iso()} accept pid={event.pid} uid={event.uid} "
            f"comm={comm}"
        )

    def _on_file(self, cpu, data, size):
        event = self._bpf_file["file_events"].event(data)
        comm = event.comm.decode("utf-8", errors="replace")
        path = event.path.decode("utf-8", errors="replace")
        if event.is_unlink:
            self._write_line(
                f"{_now_iso()} unlink pid={event.pid} comm={comm} path={path}"
            )
        else:
            flags = _decode_flags(event.flags)
            self._write_line(
                f"{_now_iso()} open pid={event.pid} comm={comm} "
                f"path={path} flags={flags}"
            )

    # ── Lifecycle ────────────────────────────────────────────────────

    def start(self, duration: int | None = None) -> None:
        """Start collecting eBPF events.

        Args:
            duration: Collection duration in seconds. None = run until stopped.
        """
        self._output_file = open(self.output_path, "w")  # noqa: SIM115
        self._running = True

        # Compile and attach BPF programs
        self._bpf_process = BPF(text=BPF_PROCESS)
        self._populate_self_pids(self._bpf_process)
        self._bpf_process["execve_events"].open_perf_buffer(self._on_execve)
        self._bpf_process["exit_events"].open_perf_buffer(self._on_exit)
        self._bpf_instances.append(self._bpf_process)

        self._bpf_network = BPF(text=BPF_NETWORK)
        self._populate_self_pids(self._bpf_network)
        self._bpf_network["connect_events"].open_perf_buffer(self._on_connect)
        self._bpf_network["accept_events"].open_perf_buffer(self._on_accept)
        self._bpf_instances.append(self._bpf_network)

        self._bpf_file = BPF(text=BPF_FILE)
        self._populate_self_pids(self._bpf_file)
        self._bpf_file["file_events"].open_perf_buffer(self._on_file)
        self._bpf_instances.append(self._bpf_file)

        print(f"eBPF collector started, writing to {self.output_path}", file=sys.stderr)

        # Install signal handler for graceful stop
        def _handle_signal(signum, frame):
            self._running = False

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

        # Poll loop
        start_time = time.monotonic()
        while self._running:
            for b in self._bpf_instances:
                b.perf_buffer_poll(timeout=100)
            if duration is not None and (time.monotonic() - start_time) >= duration:
                break

        self.stop()

    def stop(self) -> None:
        """Stop collecting and clean up."""
        self._running = False
        for b in self._bpf_instances:
            b.cleanup()
        self._bpf_instances.clear()

        if self._output_file:
            self._output_file.close()
            self._output_file = None

        print("eBPF collector stopped", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="eBPF kernel event collector for security-gym")
    parser.add_argument(
        "--output", default="/tmp/security_gym_events.log",
        help="Output file path (default: /tmp/security_gym_events.log)",
    )
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Collection duration in seconds (default: run until SIGTERM/SIGINT)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: eBPF collector requires root. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    collector = EbpfCollector(output_path=args.output)
    collector.start(duration=args.duration)


if __name__ == "__main__":
    main()
