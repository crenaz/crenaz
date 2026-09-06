#!/bin/bash

###############################################################################
# Enable Dependabot Alerts Script for GitHub Repositories
# 
# This script enables Dependabot vulnerability alerts across all repositories
# in a GitHub account. It handles both public and private repositories.
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated with repo admin access
#   - jq for JSON processing
#
# Usage:
#   ./enable-dependabot-alerts.sh [username] [--dry-run]
#   ./enable-dependabot-alerts.sh crenaz
#   ./enable-dependabot-alerts.sh crenaz --dry-run
###############################################################################

set -e

# Configuration
GITHUB_USER="${1:-crenaz}"
DRY_RUN="${2:---dry-run}"
LOG_FILE="enable-dependabot-alerts-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize log
echo "Starting Dependabot alerts enablement for user: $GITHUB_USER" | tee "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"

if [ "$DRY_RUN" = "--dry-run" ]; then
    echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}LIVE MODE - Changes will be applied${NC}" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) is not installed${NC}" | tee -a "$LOG_FILE"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed${NC}" | tee -a "$LOG_FILE"
    exit 1
fi

# Verify authentication
if ! gh auth status &> /dev/null; then
    echo -e "${RED}Error: Not authenticated with GitHub CLI${NC}" | tee -a "$LOG_FILE"
    echo "Run: gh auth login" | tee -a "$LOG_FILE"
    exit 1
fi

echo -e "${BLUE}Fetching repositories...${NC}" | tee -a "$LOG_FILE"

TOTAL_REPOS=0
ENABLED_COUNT=0
ALREADY_ENABLED=0
FAILED_COUNT=0
PAGE=1

# Paginate through all repositories
while true; do
    echo -e "${BLUE}Fetching page $PAGE...${NC}" | tee -a "$LOG_FILE"
    
    # Fetch repositories for this page
    REPOS=$(gh api -H "Accept: application/vnd.github+json" "/users/$GITHUB_USER/repos?per_page=100&page=$PAGE&sort=updated" 2>&1) || {
        echo -e "${RED}Error fetching repositories: $REPOS${NC}" | tee -a "$LOG_FILE"
        exit 1
    }
    
    REPO_COUNT=$(echo "$REPOS" | jq 'length')
    
    if [ "$REPO_COUNT" -eq 0 ]; then
        echo -e "${BLUE}No more repositories to process.${NC}" | tee -a "$LOG_FILE"
        break
    fi
    
    # Process each repository
    echo "$REPOS" | jq -c '.[]' | while read -r repo; do
        if [ -z "$repo" ]; then
            continue
        fi
        
        REPO_NAME=$(echo "$repo" | jq -r '.name')
        REPO_FULL_NAME=$(echo "$repo" | jq -r '.full_name')
        IS_PRIVATE=$(echo "$repo" | jq -r '.private')
        IS_ARCHIVED=$(echo "$repo" | jq -r '.archived')
        IS_FORK=$(echo "$repo" | jq -r '.fork')
        
        ((TOTAL_REPOS++))
        
        # Skip archived repos
        if [ "$IS_ARCHIVED" = "true" ]; then
            echo -e "${YELLOW}⊘ $REPO_NAME: Skipped (archived)${NC}" | tee -a "$LOG_FILE"
            continue
        fi
        
        # Skip forks
        if [ "$IS_FORK" = "true" ]; then
            echo -e "${YELLOW}⊘ $REPO_NAME: Skipped (fork)${NC}" | tee -a "$LOG_FILE"
            continue
        fi
        
        REPO_TYPE="public"
        if [ "$IS_PRIVATE" = "true" ]; then
            REPO_TYPE="private"
        fi
        
        echo -e "${BLUE}Processing $REPO_NAME ($REPO_TYPE)...${NC}" | tee -a "$LOG_FILE"
        
        # Check current status of Dependabot alerts
        STATUS_RESPONSE=$(gh api -H "Accept: application/vnd.github+json" "/repos/$REPO_FULL_NAME" 2>&1) || {
            echo -e "${RED}✗ $REPO_NAME: Failed to check status${NC}" | tee -a "$LOG_FILE"
            ((FAILED_COUNT++))
            continue
        }
        
        VULNERABILITY_ALERTS_ENABLED=$(echo "$STATUS_RESPONSE" | jq -r '.security_and_analysis.secret_scanning.status // "disabled"')
        
        # For Dependabot, we need to check via a different endpoint
        # The main way is to attempt to enable it
        
        if [ "$DRY_RUN" = "--dry-run" ]; then
            echo -e "${GREEN}[DRY-RUN] Would enable Dependabot alerts for $REPO_NAME${NC}" | tee -a "$LOG_FILE"
            ((ENABLED_COUNT++))
        else
            # Enable Dependabot vulnerability alerts
            ENABLE_RESPONSE=$(gh api \
                --method PATCH \
                -H "Accept: application/vnd.github+json" \
                "/repos/$REPO_FULL_NAME" \
                -f security_and_analysis='{"dependabot_security_updates":{"status":"enabled"},"secret_scanning":{"status":"enabled"}}' \
                2>&1) || {
                echo -e "${RED}✗ $REPO_NAME: Failed to enable Dependabot alerts${NC}" | tee -a "$LOG_FILE"
                ((FAILED_COUNT++))
                continue
            }
            
            echo -e "${GREEN}✓ $REPO_NAME: Dependabot alerts enabled${NC}" | tee -a "$LOG_FILE"
            ((ENABLED_COUNT++))
        fi
    done
    
    ((PAGE++))
    
    # Check if we got a full page (if less than 100, we're on the last page)
    if [ "$REPO_COUNT" -lt 100 ]; then
        break
    fi
done

# Print summary
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}========== DEPENDABOT ENABLEMENT SUMMARY ==========${NC}" | tee -a "$LOG_FILE"
echo "Total Repositories Processed: $TOTAL_REPOS" | tee -a "$LOG_FILE"
echo "Successfully Enabled: $ENABLED_COUNT" | tee -a "$LOG_FILE"
echo "Already Enabled: $ALREADY_ENABLED" | tee -a "$LOG_FILE"
echo "Failed: $FAILED_COUNT" | tee -a "$LOG_FILE"
echo -e "${BLUE}==================================================${NC}" | tee -a "$LOG_FILE"

if [ "$DRY_RUN" = "--dry-run" ]; then
    echo -e "${YELLOW}DRY RUN COMPLETE - No changes were made${NC}" | tee -a "$LOG_FILE"
    echo "Run without --dry-run to apply changes:" | tee -a "$LOG_FILE"
    echo "  ./enable-dependabot-alerts.sh $GITHUB_USER" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}Dependabot alerts enablement complete!${NC}" | tee -a "$LOG_FILE"
fi

echo "" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
