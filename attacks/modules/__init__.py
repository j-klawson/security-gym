"""Attack modules — import all to trigger registration."""

from attacks.modules import credential_stuffing, log4shell, recon, ssh_brute_force, ssh_post_auth

__all__ = ["credential_stuffing", "log4shell", "recon", "ssh_brute_force", "ssh_post_auth"]
