#!/usr/bin/env bash
# scan-skill.sh — Deterministic security gate for safe-skill-install
#
# This script handles the security-critical path: download, harden, scan,
# and classify. The LLM agent calls this script and receives a structured
# report. The agent NEVER makes the SAFE/CAUTION/UNSAFE/FAILED decision —
# this script does, deterministically.
#
# Exit codes:
#   0 = SAFE (no medium+ findings)
#   1 = CAUTION (medium findings, no high/critical)
#   2 = UNSAFE (high or critical findings)
#   3 = FAILED (scanner error, timeout, validation failure)
#
# Usage:
#   scan-skill.sh --source <url|path> [--mode manual|auto-install|secure]
#   scan-skill.sh --local <path>
#   scan-skill.sh --check-prereqs
#
# Output: JSON report written to stdout (structured, machine-parseable)

set -euo pipefail

# --- Constants ---
readonly MIN_GIT_VERSION="2.45.1"
readonly MIN_SCANNER_VERSION="0.1.0"
readonly SCAN_TIMEOUT=120
readonly MAX_FILE_SIZE=$((5 * 1024 * 1024))  # 5MB
readonly SKILL_NAME_REGEX='^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*(@[a-zA-Z0-9._-]+)?$'
readonly OWNER_REPO_REGEX='^[a-zA-Z0-9._-]+$'
readonly BRANCH_REGEX='^[a-zA-Z0-9._/-]+$'
readonly SEARCH_QUERY_REGEX='^[a-zA-Z0-9 _-]+$'

# --- Global state ---
SCAN_DIR=""
SOURCE_URL=""
COMMIT_SHA=""
SCANNER_VERSION=""
ASSESSMENT=""
INSTALL_MODE="manual"
IS_LOCAL=false
FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_LOW=0
FINDINGS_INFO=0
FILES_SCANNED=0
SYMLINKS_REMOVED=0
LARGE_FILES_FLAGGED=0
WARNINGS=()
ERRORS=()

# --- Cleanup ---
cleanup() {
    if [[ -n "$SCAN_DIR" && "$IS_LOCAL" == "false" && -d "$SCAN_DIR" ]]; then
        rm -rf "$SCAN_DIR"
    fi
}
trap cleanup EXIT

# --- Utility functions ---
log_warning() {
    WARNINGS+=("$1")
}

log_error() {
    ERRORS+=("$1")
}

version_ge() {
    # Returns 0 if $1 >= $2 (semantic version comparison)
    local v1="$1" v2="$2"
    if [[ "$v1" == "$v2" ]]; then return 0; fi
    local IFS=.
    local i v1_parts=($v1) v2_parts=($v2)
    for ((i=0; i<${#v2_parts[@]}; i++)); do
        local a="${v1_parts[i]:-0}"
        local b="${v2_parts[i]:-0}"
        # Strip non-numeric suffixes
        a="${a%%[!0-9]*}"
        b="${b%%[!0-9]*}"
        if (( a > b )); then return 0; fi
        if (( a < b )); then return 1; fi
    done
    return 0
}

json_escape() {
    # Escape a string for safe JSON inclusion
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

emit_report() {
    # Emit structured JSON report to stdout
    local scanner_stderr=""
    if [[ -f "$SCAN_DIR/.scan-stderr.log" ]]; then
        scanner_stderr=$(head -c 4096 "$SCAN_DIR/.scan-stderr.log" 2>/dev/null || true)
    fi

    local warnings_json="[]"
    if (( ${#WARNINGS[@]} > 0 )); then
        warnings_json="["
        local first=true
        for w in "${WARNINGS[@]}"; do
            if $first; then first=false; else warnings_json+=","; fi
            warnings_json+="\"$(json_escape "$w")\""
        done
        warnings_json+="]"
    fi

    local errors_json="[]"
    if (( ${#ERRORS[@]} > 0 )); then
        errors_json="["
        local first=true
        for e in "${ERRORS[@]}"; do
            if $first; then first=false; else errors_json+=","; fi
            errors_json+="\"$(json_escape "$e")\""
        done
        errors_json+="]"
    fi

    cat <<REPORT_EOF
{
  "assessment": "$(json_escape "$ASSESSMENT")",
  "source_url": "$(json_escape "$SOURCE_URL")",
  "commit_sha": "$(json_escape "$COMMIT_SHA")",
  "scanner_version": "$(json_escape "$SCANNER_VERSION")",
  "scan_dir": "$(json_escape "$SCAN_DIR")",
  "install_mode": "$(json_escape "$INSTALL_MODE")",
  "findings": {
    "critical": $FINDINGS_CRITICAL,
    "high": $FINDINGS_HIGH,
    "medium": $FINDINGS_MEDIUM,
    "low": $FINDINGS_LOW,
    "info": $FINDINGS_INFO
  },
  "files_scanned": $FILES_SCANNED,
  "symlinks_removed": $SYMLINKS_REMOVED,
  "large_files_flagged": $LARGE_FILES_FLAGGED,
  "scanner_stderr": "$(json_escape "$scanner_stderr")",
  "warnings": $warnings_json,
  "errors": $errors_json,
  "scan_output_available": true
}
REPORT_EOF
}

fail_report() {
    ASSESSMENT="FAILED"
    log_error "$1"
    emit_report
    exit 3
}

# --- Prerequisite checks ---
check_prereqs() {
    # Check skill-scanner
    if ! command -v skill-scanner &>/dev/null; then
        fail_report "skill-scanner not found. Install with: pip install cisco-ai-skill-scanner"
    fi

    # Try multiple methods to get version — --version is not supported in all releases
    SCANNER_VERSION=$(skill-scanner --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -z "$SCANNER_VERSION" ]]; then
        # Fallback: query pip metadata for the package version
        SCANNER_VERSION=$(pip3 show cisco-ai-skill-scanner 2>/dev/null | grep -i '^Version:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
    fi
    if [[ -z "$SCANNER_VERSION" ]]; then
        # Fallback: query the venv python that backs the skill-scanner binary
        local scanner_bin
        scanner_bin=$(command -v skill-scanner 2>/dev/null || true)
        if [[ -n "$scanner_bin" ]]; then
            local venv_python
            venv_python="$(dirname "$scanner_bin")/python3"
            if [[ -x "$venv_python" ]]; then
                SCANNER_VERSION=$("$venv_python" -c "import importlib.metadata; print(importlib.metadata.version('cisco-ai-skill-scanner'))" 2>/dev/null || true)
            fi
        fi
    fi
    if [[ -z "$SCANNER_VERSION" ]]; then
        log_warning "Could not determine skill-scanner version — skipping version check"
        SCANNER_VERSION="unknown"
    fi

    if [[ "$SCANNER_VERSION" != "unknown" ]] && ! version_ge "$SCANNER_VERSION" "$MIN_SCANNER_VERSION"; then
        fail_report "skill-scanner version $SCANNER_VERSION is below minimum $MIN_SCANNER_VERSION. Please upgrade."
    fi

    # Check git
    local git_version
    git_version=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -z "$git_version" ]]; then
        fail_report "Could not determine git version. Git >= $MIN_GIT_VERSION required."
    fi

    if ! version_ge "$git_version" "$MIN_GIT_VERSION"; then
        fail_report "Git version $git_version is below $MIN_GIT_VERSION. CVE-2024-32002 affects git clone operations."
    fi

    return 0
}

# --- Input validation ---
validate_owner_repo() {
    local component="$1"
    if ! printf '%s' "$component" | grep -qE "$OWNER_REPO_REGEX"; then
        fail_report "Invalid owner/repo component: contains disallowed characters"
    fi
}

validate_branch() {
    local branch="$1"
    if ! printf '%s' "$branch" | grep -qE "$BRANCH_REGEX"; then
        fail_report "Invalid branch name from API: contains disallowed characters"
    fi
}

# --- Source resolution ---
resolve_github_url() {
    local url="$1"
    local owner repo

    # Extract owner/repo from GitHub URL
    if [[ "$url" =~ github\.com[:/]([^/]+)/([^/.]+) ]]; then
        owner="${BASH_REMATCH[1]}"
        repo="${BASH_REMATCH[2]}"
        # Strip .git suffix if present
        repo="${repo%.git}"
    else
        fail_report "Could not extract owner/repo from URL: $url"
    fi

    validate_owner_repo "$owner"
    validate_owner_repo "$repo"

    # Resolve default branch
    local branch
    branch=$(gh api "repos/${owner}/${repo}" --jq '.default_branch' 2>/dev/null) || {
        # Check if it's a 404/403 (private repo)
        local http_status
        http_status=$(gh api "repos/${owner}/${repo}" 2>&1 | grep -oE 'HTTP [0-9]+' | grep -oE '[0-9]+' || echo "unknown")
        if [[ "$http_status" == "404" || "$http_status" == "403" ]]; then
            fail_report "Repository not accessible (HTTP $http_status). This may be a private repo. Clone locally and use --local."
        fi
        fail_report "Could not resolve repository: $url"
    }

    validate_branch "$branch"

    echo "${owner}|${repo}|${branch}"
}

# --- Download methods ---
download_github_archive() {
    local owner="$1" repo="$2" branch="$3"

    # Capture commit SHA first (TOCTOU protection)
    COMMIT_SHA=$(gh api "repos/${owner}/${repo}/commits/${branch}" --jq '.sha' 2>/dev/null) || {
        fail_report "Could not resolve commit SHA for ${owner}/${repo}@${branch}"
    }

    # Download archive to file (curl -f fails on HTTP errors)
    local archive_file="$SCAN_DIR/archive.tar.gz"
    if ! curl -fsSL "https://github.com/${owner}/${repo}/archive/${COMMIT_SHA}.tar.gz" \
        -o "$archive_file" 2>/dev/null; then
        log_warning "Archive download failed, falling back to hardened git clone"
        download_hardened_clone "https://github.com/${owner}/${repo}.git"
        return
    fi

    # Extract safely
    if ! tar xzf "$archive_file" -C "$SCAN_DIR" --strip-components=1 --no-same-owner --no-absolute-names 2>/dev/null; then
        rm -f "$archive_file"
        fail_report "Archive extraction failed — tar returned non-zero"
    fi

    rm -f "$archive_file"
}

download_hardened_clone() {
    local repo_url="$1"

    GIT_TERMINAL_PROMPT=0 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    git -c core.hooksPath=/dev/null \
        -c core.fsmonitor=false \
        -c core.symlinks=false \
        -c core.protectHFS=true \
        -c core.protectNTFS=true \
        -c core.autocrlf=false \
        -c filter.lfs.smudge=cat \
        -c filter.lfs.process=cat \
        -c filter.lfs.required=false \
        -c protocol.file.allow=never \
        -c receive.fsckObjects=true \
        -c transfer.fsckObjects=true \
        -c fetch.fsckObjects=true \
        clone --depth 1 --no-recurse-submodules \
        "$repo_url" "$SCAN_DIR/repo" 2>/dev/null || {
        fail_report "Hardened git clone failed for: $repo_url"
    }

    COMMIT_SHA=$(git -C "$SCAN_DIR/repo" rev-parse HEAD 2>/dev/null || echo "unknown")

    # Move contents out of repo/ subdirectory
    shopt -s dotglob
    mv "$SCAN_DIR/repo"/* "$SCAN_DIR/" 2>/dev/null || true
    shopt -u dotglob
    rm -rf "$SCAN_DIR/repo"
}

# --- Post-download hardening ---
harden_download() {
    # Remove .git directory
    rm -rf "$SCAN_DIR/.git" "$SCAN_DIR/repo/.git" 2>/dev/null || true

    # Strip executable bits from all files
    find "$SCAN_DIR" -type f -exec chmod 644 {} + 2>/dev/null || true

    # Remove all symlinks and count them
    local symlinks
    symlinks=$(find "$SCAN_DIR" -type l 2>/dev/null || true)
    if [[ -n "$symlinks" ]]; then
        SYMLINKS_REMOVED=$(echo "$symlinks" | wc -l | tr -d ' ')
        find "$SCAN_DIR" -type l -delete 2>/dev/null || true
        log_warning "Removed $SYMLINKS_REMOVED symlink(s) — symlinks have no legitimate use in skill content"
    fi

    # Flag large files
    local large_files
    large_files=$(find "$SCAN_DIR" -type f -size +5M 2>/dev/null || true)
    if [[ -n "$large_files" ]]; then
        LARGE_FILES_FLAGGED=$(echo "$large_files" | wc -l | tr -d ' ')
        log_warning "Found $LARGE_FILES_FLAGGED file(s) over 5MB — unusual for skill content"
    fi
}

# --- Scanner execution ---
run_scanner() {
    local scan_path="$1"
    local scanner_output
    local scanner_exit_code

    # Run scanner with timeout, separating stdout from stderr
    scanner_exit_code=0
    timeout "$SCAN_TIMEOUT" skill-scanner scan "$scan_path" --format json --use-behavioral \
        >"$SCAN_DIR/.scan-output.json" \
        2>"$SCAN_DIR/.scan-stderr.log" || scanner_exit_code=$?

    # Check for timeout (exit code 124)
    if [[ "$scanner_exit_code" -eq 124 ]]; then
        fail_report "Scanner timed out after ${SCAN_TIMEOUT}s — BLOCKED"
    fi

    # Check for scanner error
    if [[ "$scanner_exit_code" -ne 0 ]]; then
        fail_report "Scanner exited with code $scanner_exit_code — BLOCKED"
    fi

    # Check output exists and is non-empty
    if [[ ! -s "$SCAN_DIR/.scan-output.json" ]]; then
        fail_report "Scanner produced no output — BLOCKED"
    fi

    # Parse scanner output in a single Python invocation.
    # SECURITY: All paths passed via sys.argv, never interpolated into code.
    # SECURITY: Fails closed — any parse error exits non-zero, caught below.
    local parse_output
    local has_python_files="false"
    if find "$scan_path" -name '*.py' -type f 2>/dev/null | grep -q .; then
        has_python_files="true"
    fi

    parse_output=$(python3 - "$SCAN_DIR/.scan-output.json" "$SCAN_DIR" <<'PYEOF'
import json, sys, os

scan_output_path = sys.argv[1]
scan_dir = sys.argv[2]

# Parse JSON — fail hard if unparseable
try:
    with open(scan_output_path) as f:
        data = json.load(f)
except (json.JSONDecodeError, FileNotFoundError, IOError) as e:
    print(f"ERROR:parse_failed:{e}", file=sys.stderr)
    sys.exit(1)

# Extract findings — support both list and dict schemas
findings = data.get('findings', data.get('results', []))
counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

if isinstance(findings, list):
    for f in findings:
        sev = f.get('severity', '').upper() if isinstance(f, dict) else ''
        if sev in counts:
            counts[sev] += 1
elif isinstance(findings, dict):
    for sev in counts:
        counts[sev] = int(findings.get(sev.lower(), 0))
else:
    print("ERROR:unexpected_findings_type", file=sys.stderr)
    sys.exit(1)

# Files scanned count (vacuous pass protection)
files_scanned = data.get('files_scanned', data.get('summary', {}).get('files_scanned', -1))
if files_scanned == -1:
    # Fallback: count files in scan dir
    files_scanned = sum(
        1 for root, dirs, files in os.walk(scan_dir)
        for fname in files if not fname.startswith('.scan-')
    )

# Check for behavioral engine results
has_behavioral = 'behavioral' in data or any(
    f.get('engine', '').lower() == 'behavioral'
    for f in (findings if isinstance(findings, list) else [])
    if isinstance(f, dict)
)

# Output all values on separate lines in a fixed order
# Format: CRITICAL|HIGH|MEDIUM|LOW|INFO|FILES_SCANNED|HAS_BEHAVIORAL
print(f"{counts['CRITICAL']}|{counts['HIGH']}|{counts['MEDIUM']}|{counts['LOW']}|{counts['INFO']}|{files_scanned}|{'yes' if has_behavioral else 'no'}")
PYEOF
    ) || {
        fail_report "Failed to parse scanner output — BLOCKED"
    }

    # Validate the parse output format (must be 7 pipe-separated fields)
    if [[ ! "$parse_output" =~ ^[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|(yes|no)$ ]]; then
        fail_report "Scanner output parser returned unexpected format: $(echo "$parse_output" | head -c 100) — BLOCKED"
    fi

    # Split parsed values
    IFS='|' read -r FINDINGS_CRITICAL FINDINGS_HIGH FINDINGS_MEDIUM FINDINGS_LOW FINDINGS_INFO FILES_SCANNED has_behavioral <<< "$parse_output"

    # Vacuous pass protection
    if [[ "$FILES_SCANNED" -eq 0 ]]; then
        fail_report "Scanner reported zero files scanned — vacuous pass detected — BLOCKED"
    fi

    # Behavioral engine verification
    if [[ "$has_python_files" == "true" && "$has_behavioral" == "no" ]]; then
        log_warning "Python files present but behavioral engine results not found in output — coverage gap"
    fi
}

# --- Supplementary analysis (obfuscation and evasion detection) ---
# These checks are defense-in-depth layers. They are NOT comprehensive and can be evaded.
# Active patterns have low-to-moderate false-positive rates.
# Higher-FP patterns are commented out — uncomment for higher-sensitivity scanning.
run_supplementary_analysis() {
    local scan_path="$1"

    # --- Category 1: Dangerous command patterns ---
    # Low false-positive rate: these commands are uncommon in legitimate skill config files
    local dangerous_files
    dangerous_files=$(grep -rloI 'curl\|wget\|eval\|nc \|subprocess\|os\.system' "$scan_path" \
        --include='*.sh' --include='*.js' --include='*.ts' \
        --include='*.yaml' --include='*.yml' --include='*.md' --include='*.json' 2>/dev/null || true)
    if [[ -n "$dangerous_files" ]]; then
        local count
        count=$(echo "$dangerous_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found potentially dangerous commands in $count file(s)"
    fi

    # --- Category 2: Obfuscation indicators ---

    # 2a. Long base64 strings (>60 chars to reduce FP from data URIs, package hashes, etc.)
    local b64_files
    b64_files=$(grep -rloIE '[A-Za-z0-9+/]{60,}={0,2}' "$scan_path" \
        --include='*.sh' --include='*.js' --include='*.ts' --include='*.py' \
        --include='*.yaml' --include='*.yml' --include='*.md' 2>/dev/null || true)
    if [[ -n "$b64_files" ]]; then
        local count
        count=$(echo "$b64_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found long base64-like strings in $count file(s) — possible obfuscation"
    fi

    # 2b. Hex-encoded byte sequences (\xNN repeated 8+ times — common in shellcode/obfuscated payloads)
    local hex_files
    hex_files=$(grep -rloIE '(\\x[0-9a-fA-F]{2}){8,}' "$scan_path" \
        --include='*.sh' --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null || true)
    if [[ -n "$hex_files" ]]; then
        local count
        count=$(echo "$hex_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found hex-encoded byte sequences in $count file(s) — possible obfuscation"
    fi

    # 2c. Non-ASCII in script files (possible unicode homoglyph attack)
    # Uses LC_ALL=C for portable non-ASCII detection (grep -P is not available on macOS)
    local unicode_files
    unicode_files=$(LC_ALL=C grep -rloI '[^[:print:][:space:]]' "$scan_path" \
        --include='*.sh' --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null || true)
    if [[ -n "$unicode_files" ]]; then
        local count
        count=$(echo "$unicode_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found non-ASCII characters in $count script file(s) — possible unicode obfuscation"
    fi

    # 2d. Decode/reverse patterns (rev, xxd -r, ROT13 via tr)
    local decode_files
    decode_files=$(grep -rloIE '\brev\b.*\||\|\s*\brev\b|xxd\s+-r|\btr\b.*A-Za-z.*N-ZA-Mn-za-m' "$scan_path" \
        --include='*.sh' --include='*.py' 2>/dev/null || true)
    if [[ -n "$decode_files" ]]; then
        local count
        count=$(echo "$decode_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found decode/reverse patterns in $count file(s) — possible obfuscation"
    fi

    # --- Category 3: Suspicious runtime patterns ---

    # 3a. Environment variable / secret access patterns
    local env_access_files
    env_access_files=$(grep -rloI 'environ\|process\.env\|os\.getenv\|\$[A-Z_]*KEY\|\$[A-Z_]*SECRET\|\$[A-Z_]*TOKEN' "$scan_path" \
        --include='*.sh' --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null || true)
    if [[ -n "$env_access_files" ]]; then
        local count
        count=$(echo "$env_access_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found environment/secret access patterns in $count file(s)"
    fi

    # 3b. Shell execution from non-shell files (sh -c, bash -c, /bin/sh, source <())
    local shell_exec_files
    shell_exec_files=$(grep -rloIE 'bash\s+-c|sh\s+-c|/bin/sh|source\s+<\(' "$scan_path" \
        --include='*.py' --include='*.js' --include='*.ts' \
        --include='*.yaml' --include='*.yml' --include='*.md' --include='*.json' 2>/dev/null || true)
    if [[ -n "$shell_exec_files" ]]; then
        local count
        count=$(echo "$shell_exec_files" | wc -l | tr -d ' ')
        log_warning "Supplementary: found shell execution patterns in $count non-shell file(s)"
    fi

    # --- Category 4: Higher false-positive patterns (commented out by default) ---
    # Uncomment for higher-sensitivity scanning (e.g., SECURE mode, unknown publishers).
    # Each is annotated with its false-positive risk level and common FP triggers.

    # 4a. String concatenation to build command names
    # FP RISK: HIGH — legitimate code frequently concatenates strings for paths, URLs, messages
    # Would detect: "cu" + "rl", 'ev' + 'al'
    # Common FP triggers: URL construction, template literals, path joining
    # local concat_files
    # concat_files=$(grep -rloIE "\"[a-z]{2,4}\"\s*\+\s*\"[a-z]{2,4}\"|'[a-z]{2,4}'\s*\+\s*'[a-z]{2,4}'" "$scan_path" \
    #     --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null || true)
    # if [[ -n "$concat_files" ]]; then
    #     local count
    #     count=$(echo "$concat_files" | wc -l | tr -d ' ')
    #     log_warning "Supplementary: found short string concatenation in $count file(s) — possible command name obfuscation"
    # fi

    # 4b. Variable indirection to resolve command names
    # FP RISK: MODERATE — some legitimate code uses computed property access, dynamic dispatch
    # Would detect: ${!var}, getattr(), globalThis[], window[]
    # Common FP triggers: plugin systems, config-driven dispatch, test frameworks
    # local indirect_files
    # indirect_files=$(grep -rloIE '\$\{![a-zA-Z_]+\}|getattr\s*\(|globalThis\[|window\[' "$scan_path" \
    #     --include='*.sh' --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null || true)
    # if [[ -n "$indirect_files" ]]; then
    #     local count
    #     count=$(echo "$indirect_files" | wc -l | tr -d ' ')
    #     log_warning "Supplementary: found variable indirection patterns in $count file(s) — possible command name obfuscation"
    # fi

    # 4c. Very long lines in non-minified files (possible embedded binary/steganographic data)
    # FP RISK: HIGH — SVG data URIs, inline CSS, base64 font embeds
    # Would detect: lines >2000 chars in text files
    # Common FP triggers: any file with embedded assets, auto-generated code
    # local steg_files
    # steg_files=$(awk 'length > 2000 {print FILENAME; nextfile}' "$scan_path"/**/*.{sh,py,yaml,yml,md} 2>/dev/null || true)
    # if [[ -n "$steg_files" ]]; then
    #     local count
    #     count=$(echo "$steg_files" | wc -l | tr -d ' ')
    #     log_warning "Supplementary: found very long lines in $count file(s) — possible embedded binary data"
    # fi
}

# --- Assessment classification (DETERMINISTIC — no LLM involved) ---
classify_assessment() {
    if (( FINDINGS_CRITICAL > 0 || FINDINGS_HIGH > 0 )); then
        ASSESSMENT="UNSAFE"
    elif (( FINDINGS_MEDIUM > 0 )); then
        ASSESSMENT="CAUTION"
    else
        ASSESSMENT="SAFE"
    fi
}

# --- Config integrity check ---
check_config_integrity() {
    local config_file="${HOME}/.config/safe-skill-install/config.json"
    if [[ ! -f "$config_file" ]]; then
        return 0
    fi

    local config_result

    # Single Python invocation for config parsing — paths via sys.argv, not interpolation
    # Returns: stored_hash|computed_hash|install_mode
    # Fails closed: any error returns empty, triggering fallback to MANUAL
    config_result=$(python3 - "$config_file" <<'PYEOF'
import json, hashlib, sys
try:
    config_path = sys.argv[1]
    with open(config_path) as f:
        data = json.load(f)
    stored_hash = data.get('config_hash', '')
    if not stored_hash:
        print('||manual')
        sys.exit(0)
    data_copy = dict(data)
    data_copy.pop('config_hash', None)
    canonical = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
    computed_hash = hashlib.sha256(canonical.encode()).hexdigest()
    install_mode = data.get('install_mode', 'manual')
    print(f'{stored_hash}|{computed_hash}|{install_mode}')
except Exception:
    print('||manual')
PYEOF
    ) || config_result="||manual"

    local stored_hash computed_hash config_mode
    IFS='|' read -r stored_hash computed_hash config_mode <<< "$config_result"

    if [[ -z "$stored_hash" ]]; then
        log_warning "Config file has no integrity hash — ignoring persisted config"
        return 1
    fi

    if [[ "$stored_hash" != "$computed_hash" ]]; then
        log_warning "CONFIG INTEGRITY CHECK FAILED — config may have been tampered with. Falling back to MANUAL mode."
        return 1
    fi

    # Validate mode against allowlist before accepting
    case "$config_mode" in
        manual|auto-install|secure)
            INSTALL_MODE="$config_mode"
            ;;
        *)
            log_warning "Config contains invalid install_mode '$config_mode' — falling back to MANUAL"
            return 1
            ;;
    esac

    return 0
}

# --- Main ---
main() {
    local source="" local_path="" check_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source)
                source="$2"
                shift 2
                ;;
            --local)
                local_path="$2"
                IS_LOCAL=true
                shift 2
                ;;
            --mode)
                case "$2" in
                    manual|auto-install|secure)
                        INSTALL_MODE="$2"
                        ;;
                    *)
                        fail_report "Invalid install mode: $2. Must be manual, auto-install, or secure."
                        ;;
                esac
                shift 2
                ;;
            --check-prereqs)
                check_only=true
                shift
                ;;
            *)
                fail_report "Unknown argument: $1"
                ;;
        esac
    done

    # Prerequisites check
    check_prereqs

    if $check_only; then
        ASSESSMENT="PREREQS_OK"
        SOURCE_URL="n/a"
        COMMIT_SHA="n/a"
        SCAN_DIR="/dev/null"
        emit_report
        exit 0
    fi

    # Config integrity check (only if mode not explicitly set)
    if [[ "$INSTALL_MODE" == "manual" ]]; then
        check_config_integrity || true
    fi

    # Handle local path
    if $IS_LOCAL; then
        if [[ ! -d "$local_path" ]]; then
            fail_report "Local path does not exist or is not a directory: $local_path"
        fi
        SCAN_DIR="$local_path"
        SOURCE_URL="$local_path"
        COMMIT_SHA="local"
    else
        # Create secure temp directory
        SCAN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/skill-scan-XXXXXXXX")
        chmod 700 "$SCAN_DIR"

        SOURCE_URL="$source"

        # Validate source URL scheme — only HTTPS allowed for remote sources
        if [[ ! "$source" =~ ^https:// ]]; then
            fail_report "Only HTTPS source URLs are supported. Got: $(echo "$source" | head -c 60)"
        fi

        # Resolve and download based on source type
        if [[ "$source" =~ github\.com ]]; then
            local resolved
            resolved=$(resolve_github_url "$source")
            local owner repo branch
            IFS='|' read -r owner repo branch <<< "$resolved"
            download_github_archive "$owner" "$repo" "$branch"
        else
            # Fallback to hardened clone for non-GitHub HTTPS URLs
            download_hardened_clone "$source"
        fi

        # Post-download hardening
        harden_download
    fi

    # Run scanner
    run_scanner "$SCAN_DIR"

    # Run supplementary analysis
    run_supplementary_analysis "$SCAN_DIR"

    # Classify assessment (deterministic)
    classify_assessment

    # Emit report
    emit_report

    # Exit with appropriate code
    case "$ASSESSMENT" in
        SAFE) exit 0 ;;
        CAUTION) exit 1 ;;
        UNSAFE) exit 2 ;;
        *) exit 3 ;;
    esac
}

main "$@"
