#!/bin/bash

###############################################################################
# Local Vulnerability Scanning Script for GitHub Repositories
# 
# This script performs local vulnerability scanning on your repositories using
# multiple scanning tools:
# 1. npm audit - for Node.js projects
# 2. pip-audit - for Python projects
# 3. Bundler audit - for Ruby projects
# 4. cargo audit - for Rust projects
# 5. OWASP Dependency-Check - comprehensive scanning (optional)
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated
#   - jq for JSON processing
#   - Individual language tools (npm, pip, bundler, cargo)
#   - Optional: OWASP Dependency-Check for advanced scanning
#
# Usage:
#   ./local-vuln-scan.sh [username] [output-dir] [--include-dependencycheck]
#   ./local-vuln-scan.sh crenaz ./scan-results
#   ./local-vuln-scan.sh crenaz ./scan-results --include-dependencycheck
###############################################################################

set -e

# Configuration
GITHUB_USER="${1:-crenaz}"
OUTPUT_DIR="${2:-.scan-results}"
INCLUDE_DEPCHECK="${3:---no-depcheck}"
TEMP_CLONE_DIR=$(mktemp -d)
LOG_FILE="$OUTPUT_DIR/scan-$(date +%Y%m%d-%H%M%S).log"
SUMMARY_FILE="$OUTPUT_DIR/vulnerability-summary.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize log
echo "Starting local vulnerability scan for user: $GITHUB_USER" | tee "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
echo "Output directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"
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

# Check available scanning tools
echo -e "${BLUE}Checking available scanning tools...${NC}" | tee -a "$LOG_FILE"

TOOLS_AVAILABLE=()
TOOLS_MISSING=()

if command -v npm &> /dev/null; then
    TOOLS_AVAILABLE+=("npm")
    echo -e "${GREEN}✓ npm audit available${NC}" | tee -a "$LOG_FILE"
else
    TOOLS_MISSING+=("npm")
    echo -e "${YELLOW}⊘ npm not found (Node.js projects won't be scanned)${NC}" | tee -a "$LOG_FILE"
fi

if command -v pip-audit &> /dev/null; then
    TOOLS_AVAILABLE+=("pip-audit")
    echo -e "${GREEN}✓ pip-audit available${NC}" | tee -a "$LOG_FILE"
else
    TOOLS_MISSING+=("pip-audit")
    echo -e "${YELLOW}⊘ pip-audit not found (Python projects won't be scanned)${NC}" | tee -a "$LOG_FILE"
fi

if command -v bundle &> /dev/null; then
    TOOLS_AVAILABLE+=("bundler")
    echo -e "${GREEN}✓ bundler audit available${NC}" | tee -a "$LOG_FILE"
else
    TOOLS_MISSING+=("bundler")
    echo -e "${YELLOW}⊘ bundler not found (Ruby projects won't be scanned)${NC}" | tee -a "$LOG_FILE"
fi

if command -v cargo &> /dev/null; then
    TOOLS_AVAILABLE+=("cargo")
    echo -e "${GREEN}✓ cargo audit available${NC}" | tee -a "$LOG_FILE"
else
    TOOLS_MISSING+=("cargo")
    echo -e "${YELLOW}⊘ cargo not found (Rust projects won't be scanned)${NC}" | tee -a "$LOG_FILE"
fi

if [ "$INCLUDE_DEPCHECK" = "--include-dependencycheck" ]; then
    if command -v dependency-check &> /dev/null; then
        TOOLS_AVAILABLE+=("dependency-check")
        echo -e "${GREEN}✓ OWASP Dependency-Check available${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${YELLOW}⊘ OWASP Dependency-Check not found (skipping)${NC}" | tee -a "$LOG_FILE"
        echo "    Install with: brew install dependency-check" | tee -a "$LOG_FILE"
    fi
fi

echo "" | tee -a "$LOG_FILE"

# Initialize summary
echo "{" > "$SUMMARY_FILE"
echo "  \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$SUMMARY_FILE"
echo "  \"user\": \"$GITHUB_USER\"," >> "$SUMMARY_FILE"
echo "  \"repositories\": [" >> "$SUMMARY_FILE"

TOTAL_REPOS=0
SCANNED_REPOS=0
REPOS_WITH_VULNS=0
TOTAL_VULNS=0
FIRST_REPO=true

# Paginate through repositories
PAGE=1
while true; do
    echo -e "${BLUE}Fetching repositories (page $PAGE)...${NC}" | tee -a "$LOG_FILE"
    
    REPOS=$(gh api -H "Accept: application/vnd.github+json" "/users/$GITHUB_USER/repos?per_page=100&page=$PAGE&sort=updated" 2>&1) || {
        echo -e "${RED}Error fetching repositories${NC}" | tee -a "$LOG_FILE"
        exit 1
    }
    
    REPO_COUNT=$(echo "$REPOS" | jq 'length')
    
    if [ "$REPO_COUNT" -eq 0 ]; then
        break
    fi
    
    echo "$REPOS" | jq -c '.[]' | while read -r repo; do
        if [ -z "$repo" ]; then
            continue
        fi
        
        REPO_NAME=$(echo "$repo" | jq -r '.name')
        REPO_FULL_NAME=$(echo "$repo" | jq -r '.full_name')
        REPO_URL=$(echo "$repo" | jq -r '.clone_url')
        IS_ARCHIVED=$(echo "$repo" | jq -r '.archived')
        IS_FORK=$(echo "$repo" | jq -r '.fork')
        
        ((TOTAL_REPOS++))
        
        # Skip archived and forked repos
        if [ "$IS_ARCHIVED" = "true" ] || [ "$IS_FORK" = "true" ]; then
            echo -e "${YELLOW}⊘ $REPO_NAME: Skipped (archived or fork)${NC}" | tee -a "$LOG_FILE"
            continue
        fi
        
        echo -e "${BLUE}Scanning $REPO_NAME...${NC}" | tee -a "$LOG_FILE"
        
        REPO_SCAN_DIR="$OUTPUT_DIR/$REPO_NAME"
        mkdir -p "$REPO_SCAN_DIR"
        
        # Clone repository
        CLONE_OUTPUT=$(git clone --depth 1 "$REPO_URL" "$TEMP_CLONE_DIR/$REPO_NAME" 2>&1) || {
            echo -e "${RED}✗ $REPO_NAME: Failed to clone${NC}" | tee -a "$LOG_FILE"
            continue
        }
        
        ((SCANNED_REPOS++))
        REPO_VULNS=0
        REPO_HAS_VULNS=false
        
        # Scan with npm
        if [ -f "$TEMP_CLONE_DIR/$REPO_NAME/package.json" ]; then
            echo -e "${BLUE}  Scanning with npm audit...${NC}" | tee -a "$LOG_FILE"
            cd "$TEMP_CLONE_DIR/$REPO_NAME"
            npm audit --json > "$REPO_SCAN_DIR/npm-audit.json" 2>&1 || true
            cd - > /dev/null
            
            NPM_VULNS=$(jq -r '.metadata.vulnerabilities.total // 0' "$REPO_SCAN_DIR/npm-audit.json" 2>/dev/null || echo "0")
            if [ "$NPM_VULNS" -gt 0 ]; then
                echo -e "${RED}  ⚠️  npm: $NPM_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
                ((REPO_VULNS+=NPM_VULNS))
                REPO_HAS_VULNS=true
            else
                echo -e "${GREEN}  ✓ npm: No vulnerabilities${NC}" | tee -a "$LOG_FILE"
            fi
        fi
        
        # Scan with pip-audit
        if [ -f "$TEMP_CLONE_DIR/$REPO_NAME/requirements.txt" ] || [ -f "$TEMP_CLONE_DIR/$REPO_NAME/setup.py" ] || [ -f "$TEMP_CLONE_DIR/$REPO_NAME/pyproject.toml" ]; then
            echo -e "${BLUE}  Scanning with pip-audit...${NC}" | tee -a "$LOG_FILE"
            cd "$TEMP_CLONE_DIR/$REPO_NAME"
            pip-audit --desc --output json > "$REPO_SCAN_DIR/pip-audit.json" 2>&1 || true
            cd - > /dev/null
            
            PIP_VULNS=$(jq -r '.vulnerabilities | length' "$REPO_SCAN_DIR/pip-audit.json" 2>/dev/null || echo "0")
            if [ "$PIP_VULNS" -gt 0 ]; then
                echo -e "${RED}  ⚠️  pip: $PIP_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
                ((REPO_VULNS+=PIP_VULNS))
                REPO_HAS_VULNS=true
            else
                echo -e "${GREEN}  ✓ pip: No vulnerabilities${NC}" | tee -a "$LOG_FILE"
            fi
        fi
        
        # Scan with bundler
        if [ -f "$TEMP_CLONE_DIR/$REPO_NAME/Gemfile.lock" ]; then
            echo -e "${BLUE}  Scanning with bundler audit...${NC}" | tee -a "$LOG_FILE"
            cd "$TEMP_CLONE_DIR/$REPO_NAME"
            bundle audit check --format json > "$REPO_SCAN_DIR/bundler-audit.json" 2>&1 || true
            cd - > /dev/null
            
            BUNDLER_VULNS=$(jq -r '.[] | length' "$REPO_SCAN_DIR/bundler-audit.json" 2>/dev/null || echo "0")
            if [ "$BUNDLER_VULNS" -gt 0 ]; then
                echo -e "${RED}  ⚠️  bundler: $BUNDLER_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
                ((REPO_VULNS+=BUNDLER_VULNS))
                REPO_HAS_VULNS=true
            else
                echo -e "${GREEN}  ✓ bundler: No vulnerabilities${NC}" | tee -a "$LOG_FILE"
            fi
        fi
        
        # Scan with cargo audit
        if [ -f "$TEMP_CLONE_DIR/$REPO_NAME/Cargo.lock" ]; then
            echo -e "${BLUE}  Scanning with cargo audit...${NC}" | tee -a "$LOG_FILE"
            cd "$TEMP_CLONE_DIR/$REPO_NAME"
            cargo audit --json > "$REPO_SCAN_DIR/cargo-audit.json" 2>&1 || true
            cd - > /dev/null
            
            CARGO_VULNS=$(jq -r '.vulnerabilities | length' "$REPO_SCAN_DIR/cargo-audit.json" 2>/dev/null || echo "0")
            if [ "$CARGO_VULNS" -gt 0 ]; then
                echo -e "${RED}  ⚠️  cargo: $CARGO_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
                ((REPO_VULNS+=CARGO_VULNS))
                REPO_HAS_VULNS=true
            else
                echo -e "${GREEN}  ✓ cargo: No vulnerabilities${NC}" | tee -a "$LOG_FILE"
            fi
        fi
        
        # Scan with OWASP Dependency-Check (if available and requested)
        if [ "$INCLUDE_DEPCHECK" = "--include-dependencycheck" ] && command -v dependency-check &> /dev/null; then
            echo -e "${BLUE}  Scanning with OWASP Dependency-Check...${NC}" | tee -a "$LOG_FILE"
            dependency-check --project "$REPO_NAME" --scan "$TEMP_CLONE_DIR/$REPO_NAME" --format JSON --out "$REPO_SCAN_DIR/dependency-check.json" > /dev/null 2>&1 || true
            
            DEPCHECK_VULNS=$(jq -r '.reportSchema.vulnerabilities | length' "$REPO_SCAN_DIR/dependency-check.json" 2>/dev/null || echo "0")
            if [ "$DEPCHECK_VULNS" -gt 0 ]; then
                echo -e "${RED}  ⚠️  dependency-check: $DEPCHECK_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
                ((REPO_VULNS+=DEPCHECK_VULNS))
                REPO_HAS_VULNS=true
            else
                echo -e "${GREEN}  ✓ dependency-check: No vulnerabilities${NC}" | tee -a "$LOG_FILE"
            fi
        fi
        
        # Add to summary
        if [ "$FIRST_REPO" = false ]; then
            echo "," >> "$SUMMARY_FILE"
        fi
        
        echo "{" >> "$SUMMARY_FILE"
        echo "  \"name\": \"$REPO_NAME\"," >> "$SUMMARY_FILE"
        echo "  \"url\": \"https://github.com/$REPO_FULL_NAME\"," >> "$SUMMARY_FILE"
        echo "  \"total_vulnerabilities\": $REPO_VULNS," >> "$SUMMARY_FILE"
        echo "  \"scan_dir\": \"$REPO_SCAN_DIR\"" >> "$SUMMARY_FILE"
        echo "}" >> "$SUMMARY_FILE"
        
        if [ "$REPO_HAS_VULNS" = true ]; then
            ((REPOS_WITH_VULNS++))
            ((TOTAL_VULNS+=REPO_VULNS))
            echo -e "${RED}Total: $REPO_VULNS vulnerability(ies)${NC}" | tee -a "$LOG_FILE"
        else
            echo -e "${GREEN}✓ No vulnerabilities found${NC}" | tee -a "$LOG_FILE"
        fi
        
        # Cleanup clone
        rm -rf "$TEMP_CLONE_DIR/$REPO_NAME"
        
        FIRST_REPO=false
        echo "" | tee -a "$LOG_FILE"
    done
    
    ((PAGE++))
    
    if [ "$REPO_COUNT" -lt 100 ]; then
        break
    fi
done

# Finalize summary
echo "" >> "$SUMMARY_FILE"
echo "  ]," >> "$SUMMARY_FILE"
echo "  \"scan_summary\": {" >> "$SUMMARY_FILE"
echo "    \"total_repositories\": $TOTAL_REPOS," >> "$SUMMARY_FILE"
echo "    \"scanned_repositories\": $SCANNED_REPOS," >> "$SUMMARY_FILE"
echo "    \"repositories_with_vulnerabilities\": $REPOS_WITH_VULNS," >> "$SUMMARY_FILE"
echo "    \"total_vulnerabilities\": $TOTAL_VULNS" >> "$SUMMARY_FILE"
echo "  }" >> "$SUMMARY_FILE"
echo "}" >> "$SUMMARY_FILE"

# Cleanup
rm -rf "$TEMP_CLONE_DIR"

# Print summary
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}========== VULNERABILITY SCAN SUMMARY ==========${NC}" | tee -a "$LOG_FILE"
echo "Total Repositories: $TOTAL_REPOS" | tee -a "$LOG_FILE"
echo "Repositories Scanned: $SCANNED_REPOS" | tee -a "$LOG_FILE"
echo "Repositories with Vulnerabilities: $REPOS_WITH_VULNS" | tee -a "$LOG_FILE"
echo "Total Vulnerabilities Found: $TOTAL_VULNS" | tee -a "$LOG_FILE"
echo -e "${BLUE}===============================================${NC}" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo -e "${GREEN}Scan complete!${NC}" | tee -a "$LOG_FILE"
echo "Results saved to: $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "Summary: $SUMMARY_FILE" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"

# Show results directory structure
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}Results structure:${NC}" | tee -a "$LOG_FILE"
ls -la "$OUTPUT_DIR" | head -20 | tee -a "$LOG_FILE"
