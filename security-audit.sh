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

# GraphQL query for Dependabot alerts
GRAPHQL_QUERY='
query($owner: String!, $first: Int!, $after: String) {
  repositoryOwner(login: $owner) {
    repositories(first: $first, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        name
        url
        isPrivate
        vulnerabilityAlerts(first: 100) {
          totalCount
          nodes {
            number
            state
            dismissReason
            securityVulnerability {
              severity
              package {
                name
                ecosystem
              }
              advisory {
                summary
                description
                cvss {
                score
                vector
              }
              firstPatchedVersion {
                identifier
              }
            }
            vulnerableManifestFilename
            vulnerableManifestPath
          }
        }
      }
    }
  }
}
'

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

# Paginate through all repositories
while true; do
    if [ -z "$CURSOR" ]; then
        RESPONSE=$(gh api graphql \
            -f owner="$GITHUB_USER" \
            -f first=100 \
            -f query="$GRAPHQL_QUERY")
    else
        RESPONSE=$(gh api graphql \
            -f owner="$GITHUB_USER" \
            -f first=100 \
            -f after="$CURSOR" \
            -f query="$GRAPHQL_QUERY")
    fi

    # Extract repositories and alerts
    REPOS=$(echo "$RESPONSE" | jq -r '.data.repositoryOwner.repositories.nodes[]')
    
    echo "$REPOS" | jq -s '.' | while IFS= read -r repo_json; do
        if [ -n "$repo_json" ] && [ "$repo_json" != "[]" ]; then
            echo "$repo_json" | jq -c '.[]' | while read -r repo; do
                REPO_NAME=$(echo "$repo" | jq -r '.name')
                REPO_URL=$(echo "$repo" | jq -r '.url')
                IS_PRIVATE=$(echo "$repo" | jq -r '.isPrivate')
                ALERT_COUNT=$(echo "$repo" | jq -r '.vulnerabilityAlerts.totalCount')
                
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
                
                echo "$repo" | jq \
                    --arg url "$REPO_URL" \
                    --arg private "$IS_PRIVATE" \
                    '{
                        name: .name,
                        url: $url,
                        isPrivate: ($private | split("") | .[0:1] | join("") == "t"),
                        alertCount: .vulnerabilityAlerts.totalCount,
                        alerts: .vulnerabilityAlerts.nodes
                    }' >> "$TEMP_FILE"
                
                FIRST_REPO=false
            done
        fi
    done
    
    # Check for next page
    HAS_NEXT=$(echo "$RESPONSE" | jq -r '.data.repositoryOwner.repositories.pageInfo.hasNextPage')
    if [ "$HAS_NEXT" = "false" ]; then
        break
    fi
    CURSOR=$(echo "$RESPONSE" | jq -r '.data.repositoryOwner.repositories.pageInfo.endCursor')
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
        (.alerts[] | "  - [\(.securityVulnerability.severity)] \(.securityVulnerability.package.name): \(.securityVulnerability.advisory.summary)\n    File: \(.vulnerableManifestPath)\n") +
        "\n"' "$OUTPUT_FILE" | tee -a "$LOG_FILE"
fi

echo "" | tee -a "$LOG_FILE"
echo -e "${GREEN}Audit complete! Report saved to: $OUTPUT_FILE${NC}" | tee -a "$LOG_FILE"
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
