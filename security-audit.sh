#!/bin/bash

###############################################################################
# Security Audit Script for GitHub Repositories
# 
# This script checks all repositories in a GitHub account for:
# 1. Dependabot vulnerability alerts
# 2. Security advisories
# 3. Generates a summary report
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated
#   - jq for JSON processing
#
# Usage:
#   ./security-audit.sh [username] [output-file]
#   ./security-audit.sh crenaz security-report.json
###############################################################################

set -e

# Configuration
GITHUB_USER="${1:-crenaz}"
OUTPUT_FILE="${2:-security-report-$(date +%Y%m%d-%H%M%S).json}"
TEMP_FILE=$(mktemp)
LOG_FILE="${OUTPUT_FILE%.json}-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize report
echo "Starting security audit for user: $GITHUB_USER" | tee "$LOG_FILE"
echo "Output will be saved to: $OUTPUT_FILE" | tee -a "$LOG_FILE"
echo "Log will be saved to: $LOG_FILE" | tee -a "$LOG_FILE"
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

echo -e "${BLUE}Fetching repository data...${NC}" | tee -a "$LOG_FILE"

# Initialize results
echo "{" > "$TEMP_FILE"
echo "  \"user\": \"$GITHUB_USER\"," >> "$TEMP_FILE"
echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$TEMP_FILE"
echo "  \"repositories\": [" >> "$TEMP_FILE"

CURSOR=""
FIRST_REPO=true
TOTAL_REPOS=0
REPOS_WITH_ALERTS=0
TOTAL_ALERTS=0
PAGE=1

# Paginate through all repositories using REST API (more reliable than GraphQL)
while true; do
    echo -e "${BLUE}Fetching repositories (page $PAGE)...${NC}" | tee -a "$LOG_FILE"
    
    # Use REST API to list repositories
    REPOS_RESPONSE=$(gh api -H "Accept: application/vnd.github+json" "/users/$GITHUB_USER/repos?per_page=100&page=$PAGE&sort=updated" 2>&1) || {
        echo -e "${RED}Error fetching repositories: $REPOS_RESPONSE${NC}" | tee -a "$LOG_FILE"
        exit 1
    }
    
    # Check if we got any repos back
    REPO_COUNT=$(echo "$REPOS_RESPONSE" | jq 'length')
    
    if [ "$REPO_COUNT" -eq 0 ]; then
        echo -e "${BLUE}No more repositories to fetch.${NC}" | tee -a "$LOG_FILE"
        break
    fi
    
    # Process each repository
    echo "$REPOS_RESPONSE" | jq -c '.[]' | while read -r repo; do
        if [ -z "$repo" ]; then
            continue
        fi
        
        REPO_NAME=$(echo "$repo" | jq -r '.name')
        REPO_URL=$(echo "$repo" | jq -r '.html_url')
        IS_PRIVATE=$(echo "$repo" | jq -r '.private')
        
        # Fetch vulnerability alerts for this specific repo
        echo -e "${BLUE}  Checking $REPO_NAME...${NC}" | tee -a "$LOG_FILE"
        
        ALERTS_RESPONSE=$(gh api -H "Accept: application/vnd.github+json" "/repos/$GITHUB_USER/$REPO_NAME/vulnerability-alerts" 2>&1) || {
            # Some repos may not have vulnerability alerts enabled
            ALERTS_RESPONSE="[]"
        }
        
        ALERT_COUNT=$(echo "$ALERTS_RESPONSE" | jq 'length')
        
        ((TOTAL_REPOS++))
        
        if [ "$ALERT_COUNT" -gt 0 ]; then
            ((REPOS_WITH_ALERTS++))
            ((TOTAL_ALERTS+=ALERT_COUNT))
            echo -e "${YELLOW}⚠️  $REPO_NAME: $ALERT_COUNT alert(s)${NC}" | tee -a "$LOG_FILE"
        else
            echo -e "${GREEN}✓ $REPO_NAME: No alerts${NC}" | tee -a "$LOG_FILE"
        fi
        
        # Add to JSON report
        if [ "$FIRST_REPO" = false ]; then
            echo "," >> "$TEMP_FILE"
        fi
        
        echo "$repo" | jq --argjson alerts "$ALERTS_RESPONSE" '{
            name: .name,
            url: .html_url,
            isPrivate: .private,
            alertCount: ($alerts | length),
            alerts: $alerts
        }' >> "$TEMP_FILE"
        
        FIRST_REPO=false
    done
    
    ((PAGE++))
    
    # Check if we got a full page (if less than 100, we're on the last page)
    if [ "$REPO_COUNT" -lt 100 ]; then
        break
    fi
done

# Finalize JSON report
echo "" >> "$TEMP_FILE"
echo "  ]," >> "$TEMP_FILE"
echo "  \"summary\": {" >> "$TEMP_FILE"
echo "    \"totalRepositories\": $TOTAL_REPOS," >> "$TEMP_FILE"
echo "    \"repositoriesWithAlerts\": $REPOS_WITH_ALERTS," >> "$TEMP_FILE"
echo "    \"totalAlerts\": $TOTAL_ALERTS" >> "$TEMP_FILE"
echo "  }" >> "$TEMP_FILE"
echo "}" >> "$TEMP_FILE"

# Move temp file to output
mv "$TEMP_FILE" "$OUTPUT_FILE"

# Print summary
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}========== SECURITY AUDIT SUMMARY ==========${NC}" | tee -a "$LOG_FILE"
echo "Total Repositories: $TOTAL_REPOS" | tee -a "$LOG_FILE"
echo "Repositories with Alerts: $REPOS_WITH_ALERTS" | tee -a "$LOG_FILE"
echo "Total Vulnerability Alerts: $TOTAL_ALERTS" | tee -a "$LOG_FILE"
echo -e "${BLUE}===========================================${NC}" | tee -a "$LOG_FILE"

# Print detailed alerts if any
if [ "$TOTAL_ALERTS" -gt 0 ]; then
    echo "" | tee -a "$LOG_FILE"
    echo -e "${RED}DETAILED ALERTS:${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    jq -r '.repositories[] | select(.alertCount > 0) | 
        "\(.name) (\(.alertCount) alerts):\n" +
        (.alerts[] | "  - [Severity: \(.security_vulnerability.severity)] \(.security_vulnerability.package.name)\n    Vulnerable Version Range: \(.vulnerable_version_range)\n    Patched Version: \(.patched_version)\n") +
        "\n"' "$OUTPUT_FILE" 2>/dev/null | tee -a "$LOG_FILE" || {
        # Fallback if the alert structure is different
        jq -r '.repositories[] | select(.alertCount > 0) | "\(.name): \(.alertCount) alert(s)"' "$OUTPUT_FILE" | tee -a "$LOG_FILE"
    }
fi

echo "" | tee -a "$LOG_FILE"
echo -e "${GREEN}Audit complete! Report saved to: $OUTPUT_FILE${NC}" | tee -a "$LOG_FILE"
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
