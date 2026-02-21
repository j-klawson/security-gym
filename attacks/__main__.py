"""CLI entry point: python -m attacks <command> [args]."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from attacks.config import load_campaign, validate_campaign
from attacks.modules.base import AttackModuleRegistry
from attacks.orchestrator import CampaignOrchestrator

# Trigger module registration
import attacks.modules  # noqa: F401


def cmd_run(args: argparse.Namespace) -> int:
    """Execute or dry-run a campaign."""
    path = Path(args.campaign)
    if not path.exists():
        print(f"Error: campaign file not found: {path}")
        return 1

    config = load_campaign(path)

    orchestrator = CampaignOrchestrator(config)

    if args.dry_run:
        plan = orchestrator.dry_run()
        print(json.dumps(plan, indent=2, default=str))
        return 0

    if args.collect_only:
        print("Error: --collect-only requires a previous run (not yet supported in CLI)")
        return 1

    campaign_id = orchestrator.run()
    print(f"\nCampaign complete: {campaign_id}")
    print(f"Database: {config.collection.db_path}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a campaign YAML file."""
    path = Path(args.campaign)
    if not path.exists():
        print(f"Error: campaign file not found: {path}")
        return 1

    errors = validate_campaign(path)
    if errors:
        print(f"Validation FAILED for {path}:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"Valid: {path}")
    return 0


def cmd_list_modules(args: argparse.Namespace) -> int:
    """List available attack modules."""
    modules = AttackModuleRegistry.available()
    print("Available attack modules:")
    for name in modules:
        module = AttackModuleRegistry.get(name)
        doc = module.__class__.__doc__ or ""
        first_line = doc.strip().split("\n")[0] if doc else "(no description)"
        print(f"  {name:20s} {first_line}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="attacks",
        description="Security-gym attack campaign framework",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    run_parser = subparsers.add_parser("run", help="Execute a campaign")
    run_parser.add_argument("campaign", help="Path to campaign YAML")
    run_parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    run_parser.add_argument("--collect-only", action="store_true", help="Re-collect logs only")
    run_parser.set_defaults(func=cmd_run)

    # validate
    val_parser = subparsers.add_parser("validate", help="Validate campaign YAML")
    val_parser.add_argument("campaign", help="Path to campaign YAML")
    val_parser.set_defaults(func=cmd_validate)

    # list-modules
    list_parser = subparsers.add_parser("list-modules", help="List attack modules")
    list_parser.set_defaults(func=cmd_list_modules)

    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
