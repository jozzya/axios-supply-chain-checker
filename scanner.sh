#!/bin/bash

# Axios Supply Chain Attack Scanner
# Attack date: March 30, 2026
# Compromised versions: axios@1.14.1, axios@0.30.4
# Phantom dependency: plain-crypto-js@4.2.1

IMPORT_FILE="$(dirname "$0")/import.json"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ──────────────────────────────────────────────
# Usage
# ──────────────────────────────────────────────

usage() {
    echo "Usage:"
    echo "  ./scanner.sh                  Scan current directory"
    echo "  ./scanner.sh /path/to/project Scan a specific project"
    echo "  ./scanner.sh --scan-dir /path Scan ALL subdirectories inside /path"
    exit 1
}

# ──────────────────────────────────────────────
# Core scan function - scans a single project
# ──────────────────────────────────────────────

scan_project() {
    local PROJECT_DIR="$1"
    local PROJECT_NAME
    PROJECT_NAME=$(basename "$PROJECT_DIR")
    local LOCKFILE="$PROJECT_DIR/package-lock.json"
    local MATCH_COUNT=0
    local IOC_COUNT=0

    # ── CHECK 1: Package-lock.json ──

    if [[ ! -f "$LOCKFILE" ]]; then
        # Try to find a lockfile deeper in the project.
        LOCKFILE=$(find "$PROJECT_DIR" -maxdepth 3 -name "package-lock.json" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | head -1)
    fi

    if [[ -z "$LOCKFILE" || ! -f "$LOCKFILE" ]]; then
        echo -e "  ${YELLOW}[SKIP]${NC} No package-lock.json found"
    else
        echo -e "  ${BOLD}[CHECK 1/6]${NC} Scanning $(basename "$LOCKFILE") ..."

        while IFS= read -r entry; do
            pkg=$(echo "$entry" | jq -r '.package')
            ver=$(echo "$entry" | jq -r '.version')
            severity=$(echo "$entry" | jq -r '.severity')
            note=$(echo "$entry" | jq -r '.note')

            CLEAN_VER=$(printf "%s" "$ver" | sed 's/^[~^> \t]*//')

            if [[ "$ver" == "*" ]]; then
                match_exists=$(jq -r \
                    --arg pkg "$pkg" '
                    def check_any:
                      ((.packages // {})."".dependencies // {} | has($pkg))
                      or
                      ((.packages // {}) | to_entries | any(.key != "" and .value.name == $pkg))
                      or
                      ((.dependencies // {}) | has($pkg));
                    check_any
                ' "$LOCKFILE")
            else
                match_exists=$(jq -r \
                    --arg pkg "$pkg" \
                    --arg ver "$ver" \
                    --arg clean_ver "$CLEAN_VER" '

                    def version_matches: . == $ver or . == $clean_ver;

                    def check_match:
                      (
                          ((.packages // {})."".dependencies // {} | has($pkg))
                          and ((.packages // {})."".dependencies[$pkg] | version_matches)
                      )
                      or
                      (
                          (.packages // {})
                          | to_entries
                          | any(
                              .key != "" and
                              .value.name == $pkg and
                              (
                                   .value.version | version_matches
                                   or (.value.dependencies?[$pkg]? | version_matches)
                              )
                          )
                      )
                      or
                      (
                          ((.dependencies // {}) | has($pkg))
                          and ((.dependencies // {})[$pkg].version | version_matches)
                      );

                    check_match
                ' "$LOCKFILE")
            fi

            if [[ "$match_exists" == "true" ]]; then
                echo -e "  ${RED}[${severity}]${NC} ${BOLD}$pkg@$ver${NC} - $note"
                MATCH_COUNT=$((MATCH_COUNT + 1))
            fi

        done < <(jq -c '.[]' "$IMPORT_FILE")

        if [[ "$MATCH_COUNT" -eq 0 ]]; then
            echo -e "  ${GREEN}[PASS]${NC} No compromised packages in lockfile"
        fi
    fi

    # ── CHECK 2: Phantom dependency ──

    echo -e "  ${BOLD}[CHECK 2/6]${NC} Checking for plain-crypto-js ..."
    PHANTOM_DIRS=$(find "$PROJECT_DIR" -type d -name "plain-crypto-js" -path "*/node_modules/*" 2>/dev/null)

    if [[ -n "$PHANTOM_DIRS" ]]; then
        echo -e "  ${RED}[CRITICAL]${NC} plain-crypto-js found in node_modules!"
        echo "$PHANTOM_DIRS" | while read -r dir; do echo -e "           ${RED}-> $dir${NC}"; done
        IOC_COUNT=$((IOC_COUNT + 1))
    else
        echo -e "  ${GREEN}[PASS]${NC} No phantom dependency"
    fi

    # ── CHECK 3: RAT artifacts ──

    echo -e "  ${BOLD}[CHECK 3/6]${NC} Checking for RAT artifacts ..."
    ARTIFACT_FOUND=false

    [[ -e "/Library/Caches/com.apple.act.mond" ]] && { echo -e "  ${RED}[CRITICAL]${NC} /Library/Caches/com.apple.act.mond (macOS RAT)"; ARTIFACT_FOUND=true; IOC_COUNT=$((IOC_COUNT + 1)); }
    [[ -e "/tmp/ld.py" ]] && { echo -e "  ${RED}[CRITICAL]${NC} /tmp/ld.py (Linux RAT)"; ARTIFACT_FOUND=true; IOC_COUNT=$((IOC_COUNT + 1)); }
    [[ -n "$(find /tmp -maxdepth 1 -name '6202033*' 2>/dev/null)" ]] && { echo -e "  ${RED}[CRITICAL]${NC} /tmp/6202033* (dropper artifacts)"; ARTIFACT_FOUND=true; IOC_COUNT=$((IOC_COUNT + 1)); }
    [[ -d "/mnt/c" && -e "/mnt/c/ProgramData/wt.exe" ]] && { echo -e "  ${RED}[CRITICAL]${NC} wt.exe (Windows RAT)"; ARTIFACT_FOUND=true; IOC_COUNT=$((IOC_COUNT + 1)); }

    if [[ "$ARTIFACT_FOUND" == false ]]; then
        echo -e "  ${GREEN}[PASS]${NC} No RAT artifacts"
    fi

    # ── CHECK 4: C&C indicators ──

    echo -e "  ${BOLD}[CHECK 4/6]${NC} Scanning for C&C indicators ..."
    C2_INDICATORS=("sfrclak.com" "callnrwise.com" "142.11.206.73" "nrwise@proton.me" "ifstap@proton.me" "OrDeR_7077")
    SCRIPT_NAME=$(basename "$0")
    C2_FOUND=false

    for indicator in "${C2_INDICATORS[@]}"; do
        hits=$(grep -r \
            --include="*.json" --include="*.js" --include="*.ts" \
            --include="*.sh" --include="*.ps1" --include="*.py" --include="*.vbs" \
            --exclude="$SCRIPT_NAME" --exclude="README.md" --exclude="import.json" \
            --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git \
            --exclude-dir=core --exclude-dir=contrib \
            -l "$indicator" "$PROJECT_DIR" 2>/dev/null)
        if [[ -n "$hits" ]]; then
            echo -e "  ${RED}[CRITICAL]${NC} C&C indicator '${BOLD}$indicator${NC}' found in:"
            echo "$hits" | while read -r f; do echo -e "           ${RED}-> $f${NC}"; done
            C2_FOUND=true
            IOC_COUNT=$((IOC_COUNT + 1))
        fi
    done

    if [[ "$C2_FOUND" == false ]]; then
        echo -e "  ${GREEN}[PASS]${NC} No C&C indicators"
    fi

    # ── CHECK 5: Installed axios version ──

    echo -e "  ${BOLD}[CHECK 5/6]${NC} Checking installed axios version ..."
    AXIOS_PKG=$(find "$PROJECT_DIR" -path "*/node_modules/axios/package.json" -maxdepth 5 2>/dev/null | head -1)

    if [[ -n "$AXIOS_PKG" ]]; then
        INSTALLED_VER=$(jq -r '.version // "unknown"' "$AXIOS_PKG")
        if [[ "$INSTALLED_VER" == "1.14.1" || "$INSTALLED_VER" == "0.30.4" ]]; then
            echo -e "  ${RED}[CRITICAL]${NC} Installed axios ${BOLD}$INSTALLED_VER${NC} is COMPROMISED!"
            IOC_COUNT=$((IOC_COUNT + 1))
        else
            echo -e "  ${GREEN}[PASS]${NC} axios $INSTALLED_VER (not compromised)"
        fi
    else
        echo -e "  ${GREEN}[INFO]${NC} No axios in node_modules"
    fi

    # ── CHECK 6: package.json version ranges that could resolve to compromised versions ──

    echo -e "  ${BOLD}[CHECK 6/6]${NC} Checking package.json for risky axios ranges ..."

    # Find all package.json files (skip node_modules/vendor).
    RISKY_FOUND=false
    while IFS= read -r pkg_file; do
        AXIOS_RANGE=$(jq -r '(.dependencies.axios // .devDependencies.axios // empty)' "$pkg_file" 2>/dev/null)
        [[ -z "$AXIOS_RANGE" ]] && continue

        # Ranges that could have resolved to axios@1.14.1 during the attack window:
        #   ^1.x.x where x <= 14  (^1.0.0 through ^1.14.0 all resolve to latest 1.x)
        #   ~1.14.x               (~1.14.0 resolves to latest 1.14.x)
        #   >=1.x, * , latest
        #
        # Ranges that could have resolved to axios@0.30.4:
        #   ^0.30.x               (^0.30.0 through ^0.30.3 resolve to latest 0.30.x)
        #   ~0.30.x               (~0.30.0 through ~0.30.3)

        IS_RISKY=false
        RISK_REASON=""

        # Check for ^1.x.x ranges (caret on 1.x resolves up to latest 1.x minor/patch).
        if [[ "$AXIOS_RANGE" =~ ^\^1\. ]]; then
            IS_RISKY=true
            RISK_REASON="caret range $AXIOS_RANGE could resolve to 1.14.1"
        # Check for ^0.30.x ranges (caret on 0.30.x resolves up to latest 0.30.x patch).
        elif [[ "$AXIOS_RANGE" =~ ^\^0\.30\. ]]; then
            IS_RISKY=true
            RISK_REASON="caret range $AXIOS_RANGE could resolve to 0.30.4"
        # Check for ~1.14.x ranges.
        elif [[ "$AXIOS_RANGE" =~ ^~1\.14\. ]]; then
            IS_RISKY=true
            RISK_REASON="tilde range $AXIOS_RANGE could resolve to 1.14.1"
        # Check for ~0.30.x ranges.
        elif [[ "$AXIOS_RANGE" =~ ^~0\.30\. ]]; then
            IS_RISKY=true
            RISK_REASON="tilde range $AXIOS_RANGE could resolve to 0.30.4"
        # Wildcard / latest / star.
        elif [[ "$AXIOS_RANGE" == "*" || "$AXIOS_RANGE" == "latest" ]]; then
            IS_RISKY=true
            RISK_REASON="'$AXIOS_RANGE' would resolve to the latest published version"
        fi

        if [[ "$IS_RISKY" == true ]]; then
            REL_PATH="${pkg_file#"$PROJECT_DIR"/}"
            echo -e "  ${YELLOW}[WARN]${NC} ${BOLD}$REL_PATH${NC}: axios \"$AXIOS_RANGE\""
            echo -e "         $RISK_REASON"
            echo -e "         ${YELLOW}If npm install ran between 2026-03-31 00:21 - 03:30 UTC, a compromised"
            echo -e "         version may have been pulled. Run this scanner on every dev machine and"
            echo -e "         CI/CD runner that installed dependencies during this window.${NC}"
            RISKY_FOUND=true
            IOC_COUNT=$((IOC_COUNT + 1))
        fi

    done < <(find "$PROJECT_DIR" -name "package.json" -not -path "*/node_modules/*" -not -path "*/vendor/*" -not -path "*/.git/*" 2>/dev/null)

    if [[ "$RISKY_FOUND" == false ]]; then
        echo -e "  ${GREEN}[PASS]${NC} No risky axios version ranges"
    fi

    # ── Return result ──

    TOTAL=$((MATCH_COUNT + IOC_COUNT))
    return $TOTAL
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

echo ""
echo -e "${BOLD}Axios Supply Chain Attack Scanner${NC}"
echo -e "${CYAN}CVE: N/A (March 30, 2026 supply chain compromise)${NC}"
echo "---"

# Parse arguments.
SCAN_DIR=""
TARGET=""

if [[ "$1" == "--scan-dir" ]]; then
    if [[ -z "$2" || ! -d "$2" ]]; then
        echo -e "${RED}Error: '$2' is not a valid directory.${NC}"
        usage
    fi
    SCAN_DIR="$2"
elif [[ "$1" == "--help" || "$1" == "-h" ]]; then
    usage
elif [[ -n "$1" ]]; then
    if [[ ! -d "$1" ]]; then
        echo -e "${RED}Error: '$1' is not a valid directory.${NC}"
        usage
    fi
    TARGET="$1"
fi

# ── Single project mode ──

if [[ -z "$SCAN_DIR" ]]; then
    TARGET="${TARGET:-.}"
    echo ""
    echo -e "${BOLD}Scanning: ${CYAN}$TARGET${NC}"
    echo ""

    scan_project "$TARGET"
    TOTAL=$?

    echo ""
    echo "==========================================="
    if [[ "$TOTAL" -gt 0 ]]; then
        echo -e "${RED}${BOLD}RESULT: COMPROMISED${NC}"
        echo ""
        echo -e "${BOLD}Immediate actions:${NC}"
        echo "  1. Do NOT clean in place - rebuild from known-good state"
        echo "  2. Rotate ALL credentials (npm tokens, AWS keys, SSH keys, CI/CD secrets)"
        echo "  3. Pin to safe versions: axios@1.14.0 (1.x) or axios@0.30.3 (0.x)"
        echo "  4. Block C&C at network/DNS: sfrclak.com, callnrwise.com, 142.11.206.73"
        echo "  5. Audit CI/CD pipelines that ran npm install during exposure window"
        echo "  6. Use 'npm ci --ignore-scripts' in CI/CD as standing policy"
    else
        echo -e "${GREEN}${BOLD}RESULT: CLEAN${NC}"
        echo -e "${GREEN}No indicators of the Axios supply chain attack found.${NC}"
    fi
    echo "==========================================="
    echo ""
    exit 0
fi

# ── Multi-repo scan mode ──

echo ""
echo -e "${BOLD}Scanning all repos in: ${CYAN}$SCAN_DIR${NC}"
echo ""

TOTAL_REPOS=0
CLEAN_REPOS=0
FLAGGED_REPOS=0
FLAGGED_LIST=()

for dir in "$SCAN_DIR"/*/; do
    [[ ! -d "$dir" ]] && continue
    REPO_NAME=$(basename "$dir")
    TOTAL_REPOS=$((TOTAL_REPOS + 1))

    echo -e "${BOLD}[$TOTAL_REPOS] $REPO_NAME${NC}"

    scan_project "$dir"
    RESULT=$?

    if [[ "$RESULT" -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}>> FLAGGED ($RESULT issues)${NC}"
        FLAGGED_REPOS=$((FLAGGED_REPOS + 1))
        FLAGGED_LIST+=("$REPO_NAME ($RESULT issues)")
    else
        echo -e "  ${GREEN}>> CLEAN${NC}"
        CLEAN_REPOS=$((CLEAN_REPOS + 1))
    fi
    echo ""
done

# ── Summary ──

echo "==========================================="
echo -e "${BOLD}SCAN COMPLETE${NC}"
echo ""
echo -e "  Total repos scanned:  ${BOLD}$TOTAL_REPOS${NC}"
echo -e "  Clean:                ${GREEN}${BOLD}$CLEAN_REPOS${NC}"
echo -e "  Flagged:              ${RED}${BOLD}$FLAGGED_REPOS${NC}"

if [[ "$FLAGGED_REPOS" -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}Flagged repositories:${NC}"
    for repo in "${FLAGGED_LIST[@]}"; do
        echo -e "  ${RED}-> $repo${NC}"
    done
    echo ""
    echo -e "${BOLD}Immediate actions:${NC}"
    echo "  1. Do NOT clean in place - rebuild from known-good state"
    echo "  2. Rotate ALL credentials (npm tokens, AWS keys, SSH keys, CI/CD secrets)"
    echo "  3. Pin to safe versions: axios@1.14.0 (1.x) or axios@0.30.3 (0.x)"
    echo "  4. Block C&C at network/DNS: sfrclak.com, callnrwise.com, 142.11.206.73"
    echo "  5. Audit CI/CD pipelines that ran npm install during exposure window"
    echo "  6. Use 'npm ci --ignore-scripts' in CI/CD as standing policy"
else
    echo ""
    echo -e "${GREEN}${BOLD}All repositories are clean.${NC}"
fi
echo "==========================================="
echo ""
