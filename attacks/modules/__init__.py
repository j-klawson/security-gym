"""Attack modules — import all to trigger registration."""

from attacks.modules import log4shell, recon, ssh_brute_force

__all__ = ["log4shell", "recon", "ssh_brute_force"]
