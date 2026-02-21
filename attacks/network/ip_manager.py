"""IP aliasing setup/teardown and spoofed IP generation.

Supports two strategies:
- spoofed: Generate random IPs in a subnet for raw socket use (no OS config).
- aliased: Add/remove IP aliases on a NIC for real TCP connections.
"""

from __future__ import annotations

import atexit
import ipaddress
import logging
import platform
import random
import subprocess
from dataclasses import dataclass, field

from attacks.config import IPSourceConfig

logger = logging.getLogger(__name__)


@dataclass
class IPAllocation:
    """Tracks allocated IPs and their cleanup state."""

    ips: list[str]
    strategy: str
    interface: str | None = None
    _cleaned_up: bool = field(default=False, repr=False)


class IPManager:
    """Manages IP allocation for attack modules."""

    def __init__(self) -> None:
        self._allocations: list[IPAllocation] = []
        atexit.register(self.cleanup_all)

    def allocate(self, config: IPSourceConfig, rng: random.Random) -> list[str]:
        """Allocate IPs based on the strategy. Returns list of IP strings."""
        if config.strategy == "spoofed":
            return self._generate_spoofed(config, rng)
        elif config.strategy == "aliased":
            return self._setup_aliases(config, rng)
        else:
            raise ValueError(f"Unknown strategy: {config.strategy!r}")

    def generate_ips(self, config: IPSourceConfig, rng: random.Random) -> list[str]:
        """Compute IPs without OS changes (for dry-run previews)."""
        if config.strategy == "spoofed":
            network = ipaddress.ip_network(config.subnet, strict=False)
            hosts = list(network.hosts())
            selected = rng.sample(hosts, min(config.count, len(hosts)))
            return [str(ip) for ip in selected]
        elif config.strategy == "aliased":
            network = ipaddress.ip_network(config.subnet, strict=False)
            hosts = list(network.hosts())
            return [str(hosts[config.start_offset + i]) for i in range(config.count)]
        else:
            raise ValueError(f"Unknown strategy: {config.strategy!r}")

    def _generate_spoofed(self, config: IPSourceConfig, rng: random.Random) -> list[str]:
        """Generate random IPs within a subnet for raw socket spoofing."""
        network = ipaddress.ip_network(config.subnet, strict=False)
        hosts = list(network.hosts())
        if len(hosts) < config.count:
            raise ValueError(
                f"Subnet {config.subnet} has {len(hosts)} hosts, "
                f"need {config.count}"
            )
        selected = rng.sample(hosts, config.count)
        ips = [str(ip) for ip in selected]
        alloc = IPAllocation(ips=ips, strategy="spoofed")
        self._allocations.append(alloc)
        logger.info("Generated %d spoofed IPs in %s", len(ips), config.subnet)
        return ips

    def _setup_aliases(self, config: IPSourceConfig, rng: random.Random) -> list[str]:
        """Create IP aliases on the network interface."""
        network = ipaddress.ip_network(config.subnet, strict=False)
        hosts = list(network.hosts())

        # Generate IPs starting from offset
        ips: list[str] = []
        start = config.start_offset
        for i in range(config.count):
            idx = start + i
            if idx >= len(hosts):
                raise ValueError(
                    f"Offset {start} + count {config.count} exceeds "
                    f"available hosts in {config.subnet}"
                )
            ips.append(str(hosts[idx]))

        alloc = IPAllocation(
            ips=ips,
            strategy="aliased",
            interface=config.interface,
        )
        self._allocations.append(alloc)

        # Add aliases
        system = platform.system()
        netmask = str(network.netmask)
        for ip in ips:
            self._add_alias(ip, config.interface, netmask, system)

        logger.info(
            "Added %d IP aliases on %s (%s)",
            len(ips), config.interface, config.subnet,
        )
        return ips

    @staticmethod
    def _add_alias(ip: str, interface: str, netmask: str, system: str) -> None:
        """Add a single IP alias to the interface."""
        if system == "Darwin":
            cmd = ["ifconfig", interface, "alias", ip, "netmask", netmask]
        elif system == "Linux":
            prefix = ipaddress.ip_network(f"0.0.0.0/{netmask}").prefixlen
            cmd = ["ip", "addr", "add", f"{ip}/{prefix}", "dev", interface]
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to add alias %s: %s", ip, e.stderr.strip())
            raise

    @staticmethod
    def _remove_alias(ip: str, interface: str, netmask: str, system: str) -> None:
        """Remove a single IP alias from the interface."""
        if system == "Darwin":
            cmd = ["ifconfig", interface, "-alias", ip]
        elif system == "Linux":
            prefix = ipaddress.ip_network(f"0.0.0.0/{netmask}").prefixlen
            cmd = ["ip", "addr", "del", f"{ip}/{prefix}", "dev", interface]
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logger.debug("Failed to remove alias %s: %s", ip, e.stderr.strip())

    def cleanup_allocation(self, alloc: IPAllocation) -> None:
        """Remove aliases for a single allocation."""
        if alloc._cleaned_up:
            return
        if alloc.strategy != "aliased":
            alloc._cleaned_up = True
            return

        system = platform.system()
        interface = alloc.interface or "en0"
        # Derive netmask from the first IP (best effort)
        netmask = "255.255.255.0"

        for ip in alloc.ips:
            self._remove_alias(ip, interface, netmask, system)

        alloc._cleaned_up = True
        logger.info("Cleaned up %d aliases on %s", len(alloc.ips), interface)

    def cleanup_all(self) -> None:
        """Remove all aliased IPs. Called automatically via atexit."""
        for alloc in self._allocations:
            self.cleanup_allocation(alloc)

    @property
    def active_allocations(self) -> list[IPAllocation]:
        return [a for a in self._allocations if not a._cleaned_up]
