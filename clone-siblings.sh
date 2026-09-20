#!/usr/bin/env bash
# ==============================================================================
# clone-siblings.sh - Workspace Sibling Repository Orchestrator
# ==============================================================================
# The knowthankyew enterprise self-host suite builds container images from the
# source code of the reality engines. This script clones any missing sibling
# repositories from the knowthankyew organization and resolves naming aliases
# (e.g., care-check <-> careCheck, event-driven-ftaas <-> ml).
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Repository mapping: "LOCAL_PRIMARY:GITHUB_REPO:ALIAS"
REPOS=(
    "lease-audit:lease-audit:"
    "careCheck:care-check:care-check"
    "paystub-check:paystub-check:"
    "bill-of-rights-bot:bill-of-rights-bot:"
    "warranty-watch:warranty-watch:"
    "gradcast:gradcast:"
    "mailStripper:mail-stripper:mail-stripper"
    "ml:event-driven-ftaas:event-driven-ftaas"
    "privacy-telemetry:privacy-telemetry:"
)

VERIFY_ONLY=false
if [ "${1:-}" = "--verify-only" ]; then
    VERIFY_ONLY=true
fi

echo "Checking sibling repositories in $WORKSPACE_ROOT..."

MISSING_COUNT=0

for entry in "${REPOS[@]}"; do
    IFS=":" read -r primary gh_repo alias <<< "$entry"
    
    PRIMARY_DIR="$WORKSPACE_ROOT/$primary"
    ALIAS_DIR=""
    [ -n "$alias" ] && ALIAS_DIR="$WORKSPACE_ROOT/$alias"

    FOUND=false
    if [ -d "$PRIMARY_DIR" ]; then
        FOUND=true
    elif [ -n "$ALIAS_DIR" ] && [ -d "$ALIAS_DIR" ]; then
        FOUND=true
        # Create alias symlink if primary is missing
        if [ ! -e "$PRIMARY_DIR" ]; then
            echo "  🔗 Linking $alias -> $primary"
            ln -s "$alias" "$PRIMARY_DIR"
        fi
    fi

    # If neither exists and not verify-only, clone from GitHub
    if [ "$FOUND" = false ]; then
        if [ "$VERIFY_ONLY" = true ]; then
            echo "  ⚠️  Missing: $primary (GitHub: knowthankyew/$gh_repo)"
            MISSING_COUNT=$((MISSING_COUNT + 1))
        else
            echo "  📥 Cloning knowthankyew/$gh_repo into $primary..."
            git clone "https://github.com/knowthankyew/${gh_repo}.git" "$PRIMARY_DIR"
            if [ -n "$alias" ] && [ ! -e "$ALIAS_DIR" ]; then
                echo "  🔗 Linking $primary -> $alias"
                ln -s "$primary" "$ALIAS_DIR"
            fi
        fi
    else
        # Ensure bidirectional alias symlink exists
        if [ -n "$alias" ]; then
            if [ -d "$PRIMARY_DIR" ] && [ ! -e "$ALIAS_DIR" ]; then
                echo "  🔗 Creating alias link: $primary -> $alias"
                ln -s "$primary" "$ALIAS_DIR"
            elif [ -d "$ALIAS_DIR" ] && [ ! -e "$PRIMARY_DIR" ]; then
                echo "  🔗 Creating alias link: $alias -> $primary"
                ln -s "$alias" "$PRIMARY_DIR"
            fi
        fi
        echo "  ✅ Found: $primary"
    fi
done

if [ "$MISSING_COUNT" -gt 0 ] && [ "$VERIFY_ONLY" = true ]; then
    echo ""
    echo "❌ Missing $MISSING_COUNT sibling repositories. Run './clone-siblings.sh' to download them."
    exit 1
fi

echo ""
echo "✅ All required sibling repositories are present and linked in $WORKSPACE_ROOT."
