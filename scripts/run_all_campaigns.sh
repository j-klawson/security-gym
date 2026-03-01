#!/usr/bin/env bash
# Run all 7 attack campaigns with eBPF collection against Isildur.
#
# Each campaign appends to data/campaigns_v2.db with a unique campaign_id.
# Campaigns run sequentially — they all target the same VM.
#
# Usage:
#   ./scripts/run_all_campaigns.sh             # Run all campaigns
#   ./scripts/run_all_campaigns.sh --dry-run   # Preview without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN — no attacks will execute ==="
fi

# Campaign order: simple → complex (matches kill chain progression)
CAMPAIGNS=(
    campaigns/recon_only.yaml
    campaigns/ssh_brute_only.yaml
    campaigns/log4shell_only.yaml
    campaigns/credential_stuffing_only.yaml
    campaigns/post_auth_only.yaml
    campaigns/recon_ssh_log4shell.yaml
    campaigns/full_killchain.yaml
)

TOTAL=${#CAMPAIGNS[@]}
PASSED=0
FAILED=0

echo "=== Running $TOTAL campaigns against Isildur ==="
echo ""

for i in "${!CAMPAIGNS[@]}"; do
    campaign="${CAMPAIGNS[$i]}"
    n=$((i + 1))
    name=$(basename "$campaign" .yaml)

    echo "[$n/$TOTAL] $name"
    echo "  Config: $campaign"

    if python -m attacks run "$campaign" $DRY_RUN; then
        echo "  Result: OK"
        PASSED=$((PASSED + 1))
    else
        echo "  Result: FAILED (exit $?)"
        FAILED=$((FAILED + 1))
    fi
    echo ""
done

echo "=== Summary ==="
echo "  Passed: $PASSED / $TOTAL"
echo "  Failed: $FAILED / $TOTAL"

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "WARNING: $FAILED campaign(s) failed. Check output above."
    exit 1
fi

# Post-run validation
if [[ -z "$DRY_RUN" ]]; then
    echo ""
    echo "=== Validating labels ==="
    python scripts/validate_labels.py data/campaigns_v2.db -v
fi
