#!/bin/bash
# ==============================================================================
# Wazuh All-in-One (AIO) Architecture Upgrade Script
# Automated upgrades for central components (Indexer, Manager, Filebeat, Dashboard).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/wazuh_upgrade.log"

# Default configuration and state flags
TARGET_VERSION=""
CREDS_FILE=""
NON_INTERACTIVE=false
AUTO_UPGRADE_AGENTS=false
SKIP_AGENTS=false
SKIP_BACKUP=false
DRY_RUN=false
FORCE=false

# Global state trackers for rollback / cleanup trap
ALLOCATION_RESTORE_NEEDED=false
UPGRADE_STARTED=false
CURL_CFG=""
PREVIOUSLY_HELD_PKGS=()

# Terminal colors (auto-disabled if stdout is not a TTY)
if [[ -t 1 ]]; then
    C_RESET="\033[0m"
    C_RED="\033[1;31m"
    C_GREEN="\033[1;32m"
    C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;34m"
    C_CYAN="\033[1;36m"
    C_BOLD="\033[1m"
else
    C_RESET=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_CYAN=""
    C_BOLD=""
fi

# --- 1. Logging Functions ---
write_to_log() {
    local level="$1"
    local timestamp="$2"
    local msg="$3"
    if [[ -w "$LOG_FILE" || ( ! -e "$LOG_FILE" && -w "$(dirname "$LOG_FILE")" ) ]]; then
        echo "[$level] ${timestamp} - ${msg}" | sed -r 's/\x1B\[[0-9;]*[mK]//g' >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_info() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${C_CYAN}[INFO]${C_RESET} ${timestamp} - ${msg}"
    write_to_log "INFO" "$timestamp" "$msg"
}

log_success() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${C_GREEN}[SUCCESS]${C_RESET} ${timestamp} - ${msg}"
    write_to_log "SUCCESS" "$timestamp" "$msg"
}

log_warn() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${C_YELLOW}[WARN]${C_RESET} ${timestamp} - ${msg}"
    write_to_log "WARN" "$timestamp" "$msg"
}

log_error() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${C_RED}[ERROR]${C_RESET} ${timestamp} - ${msg}" >&2
    write_to_log "ERROR" "$timestamp" "$msg"
}

print_banner() {
    cat << "EOF"

  __          __             _       _    _           _       _       
  \ \        / /            | |     | |  | |         | |     | |      
   \ \  /\  / /_ _ _____   _| |__   | |  | |_ __   __| | __ _| |_ ___ 
    \ \/  \/ / _` |_  / | | | '_ \  | |  | | '_ \ / _` |/ _` | __/ _ \
     \  /\  / (_| |/ /| |_| | | | | | |__| | |_) | (_| | (_| | ||  __/
      \/  \/ \__,_/___|\__,_|_| |_|  \____/| .__/ \__,_|\__,_|\__\___|
                                           | |
       All-in-One Upgrade Script           |_|
==============================================================================
EOF
}

# --- 2. Cleanup & Safety Trap ---
cleanup() {
    local exit_code=$?
    
    # Restore Indexer Shard Allocation if interrupted
    if [[ "$ALLOCATION_RESTORE_NEEDED" == "true" ]]; then
        echo ""
        log_warn "⚠️ Upgrade interrupted while indexer shard routing allocation was restricted!"
        log_info "🔄 Attempting automatic restoration of cluster routing allocation to 'all'..."
        if [[ -n "${CURL_CFG:-}" && -f "$CURL_CFG" && -n "${WAZUH_INDEXER_IP:-}" ]]; then
            api_call "PUT" "/_cluster/settings" '{"persistent": {"cluster.routing.allocation.enable": "all"}}' || {
                log_error "❌ Failed to automatically restore cluster routing. Please run manually:"
                log_error "   curl -k -u <USER>:<PASS> -X PUT 'https://${WAZUH_INDEXER_IP}:9200/_cluster/settings' -H 'Content-Type: application/json' -d '{\"persistent\": {\"cluster.routing.allocation.enable\": \"all\"}}'"
            }
        fi
    fi

    # Re-apply package holds if interrupted
    if [[ ${#PREVIOUSLY_HELD_PKGS[@]} -gt 0 ]]; then
        manage_package_hold "hold" || true
    fi

    # Clean up temporary curl config file
    if [[ -n "${CURL_CFG:-}" && -f "$CURL_CFG" ]]; then
        rm -f "$CURL_CFG"
    fi

    if [[ $exit_code -ne 0 && "${UPGRADE_STARTED:-false}" == "true" ]]; then
        echo ""
        log_error "🛑 Upgrade process failed or was interrupted (exit code: $exit_code)!"
        log_info "📋 Inspect log for details: $LOG_FILE"
        log_info "🩺 Check system service status with:"
        log_info "   systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard"
    fi
}
trap cleanup EXIT INT TERM

# --- 3. Help & Usage ---
show_help() {
    cat << EOF
Wazuh All-in-One (AIO) Architecture Upgrade Script

Usage:
  sudo ./wazuh_upgrade.sh [TARGET_VERSION] [OPTIONS]

Arguments:
  TARGET_VERSION          (Optional) Target Wazuh version (e.g. 4.8.0 or v4.8.0).
                          If omitted, the script dynamically queries GitHub for latest release.

Options:
  -t, --target-version <v> Explicit target version to upgrade to.
  -c, --creds <path>       Path to credentials file (default: ./wazuh_creds).
  -y, --yes, --non-interactive
                           Run non-interactively, accepting defaults.
      --skip-agents        Skip remote agent upgrade prompt and execution.
      --upgrade-agents     Automatically dispatch remote upgrades for outdated agents.
      --skip-backup        Skip the pre-flight configuration/key backup step.
      --dry-run            Perform pre-flight, network, and version checks without modifying anything.
  -f, --force              Proceed with re-installation even if already at target version.
  -h, --help               Display this help message and exit.

Examples:
  sudo ./wazuh_upgrade.sh
  sudo ./wazuh_upgrade.sh 4.8.0
  sudo ./wazuh_upgrade.sh -t 4.8.0 --upgrade-agents -y
  sudo ./wazuh_upgrade.sh --dry-run
EOF
}

# --- 4. CLI Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target-version)
                TARGET_VERSION="${2#v}"
                shift 2
                ;;
            -c|--creds)
                CREDS_FILE="$2"
                shift 2
                ;;
            -y|--yes|--non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --skip-agents)
                SKIP_AGENTS=true
                shift
                ;;
            --upgrade-agents)
                AUTO_UPGRADE_AGENTS=true
                shift
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -*)
                log_error "🛑 Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$TARGET_VERSION" ]]; then
                    TARGET_VERSION="${1#v}"
                    shift
                else
                    log_error "🛑 Unexpected argument: $1"
                    show_help
                    exit 1
                fi
                ;;
        esac
    done
}

# --- 5. Privilege & OS Detection ---
check_prerequisites() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "🛑 This script must be run as root (or via sudo)."
        exit 1
    fi

    # Initialize log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE" 2>/dev/null || true

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_FAMILY="${ID_LIKE:-$ID}"
    else
        log_error "🛑 Cannot determine OS. /etc/os-release not found."
        exit 1
    fi

    if echo "$OS_FAMILY" | grep -qi -e 'debian' -e 'ubuntu'; then
        PKG_MANAGER="apt-get"
    elif echo "$OS_FAMILY" | grep -qi -e 'rhel' -e 'centos' -e 'fedora' -e 'almalinux' -e 'rocky'; then
        if command -v dnf >/dev/null 2>&1; then
            PKG_MANAGER="dnf"
        else
            PKG_MANAGER="yum"
        fi
    else
        log_error "🛑 Unsupported OS family: $OS_FAMILY. Only Debian/Ubuntu and RHEL derivatives are supported."
        exit 1
    fi

    log_info "🐧 Operating system detected: ${PRETTY_NAME:-$OS_FAMILY} (Package manager: $PKG_MANAGER)"
}

# --- 6. Credentials Management ---
load_credentials() {
    if [[ -z "$CREDS_FILE" ]]; then
        if [[ -f "${SCRIPT_DIR}/wazuh_creds" ]]; then
            CREDS_FILE="${SCRIPT_DIR}/wazuh_creds"
        elif [[ -f "./wazuh_creds" ]]; then
            CREDS_FILE="./wazuh_creds"
        fi
    fi

    if [[ -z "$CREDS_FILE" || ! -f "$CREDS_FILE" ]]; then
        log_error "🛑 Credentials file not found at: ${CREDS_FILE:-wazuh_creds}"
        log_error "  Please create the credentials file with mode 0600 containing:"
        log_error "  WAZUH_INDEXER_IP=127.0.0.1"
        log_error "  WAZUH_USER=admin"
        log_error "  WAZUH_PASS=YourSecretPassword"
        exit 1
    fi

    # Check and secure credentials file permissions
    local perms
    perms=$(stat -c "%a" "$CREDS_FILE" 2>/dev/null || stat -f "%Op" "$CREDS_FILE" 2>/dev/null || echo "")
    if [[ "$perms" =~ [4567]$ ]]; then
        log_warn "⚠️ Credentials file '$CREDS_FILE' has loose permissions ($perms). Enforcing 0600..."
        chmod 600 "$CREDS_FILE" 2>/dev/null || true
    fi

    # Read credentials safely
    # shellcheck source=/dev/null
    source "$CREDS_FILE"

    if [[ -z "${WAZUH_INDEXER_IP:-}" || -z "${WAZUH_USER:-}" || -z "${WAZUH_PASS:-}" ]]; then
        log_error "🛑 Missing required variables in $CREDS_FILE (WAZUH_INDEXER_IP, WAZUH_USER, WAZUH_PASS)"
        exit 1
    fi

    # Setup CA certificate validation
    WAZUH_CACERT="/etc/wazuh-indexer/certs/root-ca.pem"
    CURL_OPTS=(-sS)

    if [[ ! -f "$WAZUH_CACERT" ]]; then
        log_warn "⚠️ CA certificate not found at $WAZUH_CACERT. Falling back to insecure mode (-k)."
        if [[ "$WAZUH_INDEXER_IP" != "127.0.0.1" && "$WAZUH_INDEXER_IP" != "localhost" && "$WAZUH_INDEXER_IP" != "::1" ]]; then
            log_error "🛑 Insecure curl (-k) is ONLY permitted for loopback/localhost targets."
            log_error "  Target IP '$WAZUH_INDEXER_IP' is non-local and susceptible to MITM."
            log_error "  Please ensure the indexer root CA certificate exists at $WAZUH_CACERT."
            exit 1
        fi
        CURL_OPTS+=("-k")
    else
        log_info "🔒 Using CA certificate $WAZUH_CACERT for strict TLS validation."
        CURL_OPTS+=("--cacert" "$WAZUH_CACERT")
    fi

    # Create temporary curl config file to avoid leaking credentials in process table
    CURL_CFG=$(mktemp /tmp/wazuh_curl_XXXXXX.cfg)
    chmod 600 "$CURL_CFG"
    cat > "$CURL_CFG" <<EOF
user = "${WAZUH_USER}:${WAZUH_PASS}"
EOF
}

# --- 7. API Wrapper ---
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local resp_file
    resp_file=$(mktemp /tmp/wazuh_resp_XXXXXX.json)
    chmod 600 "$resp_file"
    
    local cmd=(curl "${CURL_OPTS[@]}" --config "$CURL_CFG" -s -o "$resp_file" -w "%{http_code}" -X "$method" "https://${WAZUH_INDEXER_IP}:9200${endpoint}")
    if [[ -n "$data" ]]; then
        cmd+=(-H "Content-Type: application/json" -d "$data")
    fi

    local http_code
    http_code=$("${cmd[@]}" || echo "000")

    if [[ "$http_code" -lt 200 || "$http_code" -gt 299 ]]; then
        log_error "🛑 API call [$method $endpoint] failed with HTTP status $http_code."
        if [[ -s "$resp_file" ]]; then
            log_error "  Indexer response: $(cat "$resp_file" | tr -d '\r\n')"
        fi
        rm -f "$resp_file"
        return 1
    fi

    rm -f "$resp_file"
    return 0
}

# --- 8. Dynamic Version Resolution & Asset Mapping ---
resolve_versions_and_assets() {
    if [[ -z "$TARGET_VERSION" ]]; then
        log_info "🔍 No target version specified. Querying GitHub API for latest Wazuh release..."
        local gh_release
        gh_release=$(curl -sS --connect-timeout 10 "https://api.github.com/repos/wazuh/wazuh/releases/latest" 2>/dev/null || true)
        LATEST_TAG=$(echo "$gh_release" | grep -Po '(?<="tag_name": "v)[^"]*' || true)
        
        if [[ -z "$LATEST_TAG" ]]; then
            log_error "🛑 Failed to resolve latest version from GitHub API (possible rate-limiting or network error)."
            log_error "  Please specify the target version explicitly, e.g.:"
            log_error "  sudo $0 4.8.0"
            exit 1
        fi
        TARGET_VERSION="$LATEST_TAG"
        log_info "🎯 Dynamically resolved latest target version to: v$TARGET_VERSION"
    else
        log_info "🎯 Target version specified by user: v$TARGET_VERSION"
    fi

    # Map Filebeat module version
    local major minor
    major=$(echo "$TARGET_VERSION" | cut -d. -f1)
    minor=$(echo "$TARGET_VERSION" | cut -d. -f2)

    if [[ "$major" -eq 4 ]]; then
        if [[ "$minor" -le 7 ]]; then
            FB_MOD_VER="0.3"
        elif [[ "$minor" -le 13 ]]; then
            FB_MOD_VER="0.4"
        else
            FB_MOD_VER="0.5"
        fi
    else
        FB_MOD_VER="0.5"
    fi

    TEMPLATE_URL="https://raw.githubusercontent.com/wazuh/wazuh/v${TARGET_VERSION}/extensions/elasticsearch/7.x/wazuh-template.json"
    FILEBEAT_MODULE_URL="https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-${FB_MOD_VER}.tar.gz"

    log_info "🌐 Target assets configured:"
    log_info "  📄 Elasticsearch/Indexer Template: $TEMPLATE_URL"
    log_info "  📦 Filebeat Module (v${FB_MOD_VER}): $FILEBEAT_MODULE_URL"
}

# --- 9. Current Version Detection ---
detect_current_version() {
    local ver=""
    if [[ -x /var/ossec/bin/wazuh-control ]]; then
        ver=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -E '^WAZUH_VERSION=' | cut -d'"' -f2 || true)
    fi
    if [[ -z "$ver" && -f /etc/ossec-init.conf ]]; then
        ver=$(grep -E '^VERSION=' /etc/ossec-init.conf 2>/dev/null | cut -d'"' -f2 || true)
    fi
    if [[ -z "$ver" ]]; then
        if [[ "$PKG_MANAGER" == "apt-get" ]]; then
            ver=$(dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null | cut -d'-' -f1 || true)
        else
            ver=$(rpm -q --qf '%{VERSION}' wazuh-manager 2>/dev/null || true)
        fi
    fi
    echo "${ver#v}"
}

# --- 10. Pre-Flight Checks ---
check_disk_space() {
    local path="$1"
    local min_mb="${2:-5120}"

    if [[ ! -d "$path" ]]; then
        return 0
    fi

    # -P ensures POSIX output format to prevent device name line-wrapping
    local free_mb
    free_mb=$(df -mP "$path" 2>/dev/null | awk 'NR==2 {print $4}')

    if [[ -z "$free_mb" || "$free_mb" -lt "$min_mb" ]]; then
        log_error "🛑 Insufficient disk space on '$path': ${free_mb:-0}MB free, required: ${min_mb}MB."
        return 1
    fi
    log_info "💾 Disk space check on '$path': ${free_mb}MB available (min: ${min_mb}MB)."
    return 0
}

run_preflight_checks() {
    log_info "🛫 Running pre-flight system health checks..."

    # Check disk space on root and /var (where indexer data and manager logs live)
    check_disk_space "/" 5120 || exit 1
    if [[ -d "/var" ]]; then
        check_disk_space "/var" 5120 || exit 1
    fi

    # Check wazuh-manager service
    if ! systemctl is-active --quiet wazuh-manager; then
        log_error "🛑 Service 'wazuh-manager' is not active. The cluster must be running and healthy before upgrading."
        exit 1
    fi
    log_info "🟢 Service 'wazuh-manager' is running."

    # Check wazuh-indexer service and API authentication
    if ! systemctl is-active --quiet wazuh-indexer; then
        log_error "🛑 Service 'wazuh-indexer' is not active. Ensure indexer is running before upgrading."
        exit 1
    fi

    log_info "🔌 Testing connectivity and credentials against Indexer API..."
    local test_code
    test_code=$(curl "${CURL_OPTS[@]}" --config "$CURL_CFG" -s -o /dev/null -w "%{http_code}" -X GET "https://${WAZUH_INDEXER_IP}:9200/" || echo "000")
    if [[ "$test_code" != "200" ]]; then
        log_error "🛑 Failed to authenticate to Wazuh Indexer API at https://${WAZUH_INDEXER_IP}:9200 (HTTP $test_code)."
        log_error "  Please verify WAZUH_USER and WAZUH_PASS in '$CREDS_FILE'."
        exit 1
    fi
    log_info "🟢 Successfully authenticated with Wazuh Indexer API."

    # Check current version
    CURRENT_VERSION=$(detect_current_version)
    if [[ -n "$CURRENT_VERSION" ]]; then
        log_info "📋 Currently installed Wazuh Manager version: v$CURRENT_VERSION"
        if [[ "$CURRENT_VERSION" == "$TARGET_VERSION" ]]; then
            log_warn "⚠️ Installed version ($CURRENT_VERSION) is already identical to target version ($TARGET_VERSION)!"
            if [[ "$FORCE" != "true" ]]; then
                if [[ "$NON_INTERACTIVE" == "true" || ! -t 0 ]]; then
                    log_info "🛑 Exiting since system is already at target version (use --force to reinstall)."
                    exit 0
                fi
                read -r -p "Do you want to re-run the upgrade process anyway? (y/N): " proceed
                if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
                    log_info "🛑 Operation aborted by user."
                    exit 0
                fi
            fi
        fi
    fi

    # Verify asset availability
    log_info "🌐 Validating download availability of remote assets..."
    if ! curl -sSfLI "$FILEBEAT_MODULE_URL" >/dev/null 2>&1; then
        log_warn "⚠️ Filebeat module v${FB_MOD_VER} not found at: $FILEBEAT_MODULE_URL"
        if [[ "$FB_MOD_VER" == "0.5" ]]; then
            log_info "  Attempting fallback to module v0.4..."
            FILEBEAT_MODULE_URL="https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz"
            if curl -sSfLI "$FILEBEAT_MODULE_URL" >/dev/null 2>&1; then
                log_info "  ✅ Fallback to module v0.4 verified."
            else
                log_error "🛑 Filebeat module download failed for both v0.5 and v0.4."
                exit 1
            fi
        fi
    else
        log_info "  ✅ Filebeat module URL verified."
    fi

    if ! curl -sSfLI "$TEMPLATE_URL" >/dev/null 2>&1; then
        log_error "🛑 Wazuh Elasticsearch template not reachable at: $TEMPLATE_URL"
        exit 1
    fi
    log_info "  ✅ Wazuh Indexer template URL verified."

    log_success "All pre-flight checks passed."
}

# --- 11. Configuration & Key Backup ---
backup_configurations() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_info "⏭️ Skipping configuration backup (--skip-backup specified)."
        return 0
    fi

    log_info "💾 Creating pre-upgrade configuration and key backup..."
    local backup_dir="/var/backups/wazuh"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    local archive="${backup_dir}/wazuh_backup_${timestamp}.tar.gz"

    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"

    local paths=()
    [[ -d /var/ossec/etc ]] && paths+=(/var/ossec/etc)
    [[ -d /etc/wazuh-indexer ]] && paths+=(/etc/wazuh-indexer)
    [[ -d /etc/wazuh-dashboard ]] && paths+=(/etc/wazuh-dashboard)
    [[ -d /etc/filebeat ]] && paths+=(/etc/filebeat)

    if [[ ${#paths[@]} -gt 0 ]]; then
        tar -czf "$archive" "${paths[@]}" >> "$LOG_FILE" 2>&1 || {
            log_warn "⚠️ Backup completed with non-fatal warnings (see $LOG_FILE)."
        }
        chmod 600 "$archive"
        log_success "Configuration backup securely created at: $archive"
    else
        log_warn "⚠️ No Wazuh configuration directories were found to back up."
    fi
}

# --- 12. Repository Configuration & Package Holds ---
configure_repository() {
    log_info "📦 Configuring official Wazuh repositories..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y apt-transport-https curl gnupg >> "$LOG_FILE" 2>&1
        
        mkdir -p /usr/share/keyrings
        curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>>"$LOG_FILE" || true
        chmod 644 /usr/share/keyrings/wazuh.gpg
        
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update >> "$LOG_FILE" 2>&1
    else
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH >> "$LOG_FILE" 2>&1
        cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        $PKG_MANAGER makecache >> "$LOG_FILE" 2>&1 || true
    fi
    log_success "Package repository configured."
}

manage_package_hold() {
    local action="$1" # "unhold" or "hold"
    local pkgs=(wazuh-indexer wazuh-manager wazuh-dashboard filebeat)

    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        if command -v apt-mark >/dev/null 2>&1; then
            if [[ "$action" == "unhold" ]]; then
                local held_pkgs
                held_pkgs=$(apt-mark showhold 2>/dev/null || true)
                for p in "${pkgs[@]}"; do
                    if echo "$held_pkgs" | grep -qw "$p"; then
                        log_info "🔓 Unholding package: $p for upgrade..."
                        apt-mark unhold "$p" >> "$LOG_FILE" 2>&1 || true
                        PREVIOUSLY_HELD_PKGS+=("$p")
                    fi
                done
            elif [[ "$action" == "hold" ]]; then
                for p in "${PREVIOUSLY_HELD_PKGS[@]}"; do
                    log_info "🔒 Re-holding package: $p..."
                    apt-mark hold "$p" >> "$LOG_FILE" 2>&1 || true
                done
            fi
        fi
    else
        if command -v yum >/dev/null 2>&1 && yum help versionlock >/dev/null 2>&1; then
            if [[ "$action" == "unhold" ]]; then
                for p in "${pkgs[@]}"; do
                    if yum versionlock list 2>/dev/null | grep -qw "$p"; then
                        log_info "🔓 Removing versionlock for package: $p..."
                        yum versionlock delete "$p" >> "$LOG_FILE" 2>&1 || true
                        PREVIOUSLY_HELD_PKGS+=("$p")
                    fi
                done
            elif [[ "$action" == "hold" ]]; then
                for p in "${PREVIOUSLY_HELD_PKGS[@]}"; do
                    log_info "🔒 Re-applying versionlock for package: $p..."
                    yum versionlock add "$p" >> "$LOG_FILE" 2>&1 || true
                done
            fi
        fi
    fi
}

update_package() {
    local pkg="$1"
    local target_spec=""

    log_info "📦 Upgrading package: $pkg..."

    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        local apt_flags=(-y --only-upgrade -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")
        
        # Pin version if an explicit target is set and not filebeat
        if [[ "$pkg" != "filebeat" && -n "${TARGET_VERSION:-}" ]]; then
            local match_ver
            match_ver=$(apt-cache madison "$pkg" 2>/dev/null | awk '{print $3}' | grep -E "^${TARGET_VERSION}(-|$)" | head -n 1 || true)
            if [[ -n "$match_ver" ]]; then
                log_info "  Targeting exact APT version: $pkg=$match_ver"
                target_spec="=${match_ver}"
            fi
        fi

        apt-get install "${apt_flags[@]}" "${pkg}${target_spec}" >> "$LOG_FILE" 2>&1 || {
            log_error "🛑 Package manager failed while upgrading: $pkg"
            return 1
        }
    else
        if [[ "$pkg" != "filebeat" && -n "${TARGET_VERSION:-}" ]]; then
            if $PKG_MANAGER list available "${pkg}-${TARGET_VERSION}*" >> "$LOG_FILE" 2>&1; then
                target_spec="-${TARGET_VERSION}"
            fi
        fi

        $PKG_MANAGER upgrade -y "${pkg}${target_spec}" >> "$LOG_FILE" 2>&1 || {
            log_error "🛑 Package manager failed while upgrading: $pkg"
            return 1
        }
    fi
    log_success "Package $pkg upgraded."
}

# --- 13. Component Upgrade Procedures ---
upgrade_indexer() {
    log_info "=================================================================="
    log_info "1️⃣ Upgrading Wazuh Indexer Core..."
    log_info "=================================================================="

    log_info "🔒 Disabling replica routing allocation on logic tier..."
    api_call "PUT" "/_cluster/settings" '{"persistent": {"cluster.routing.allocation.enable": "primaries"}}'
    ALLOCATION_RESTORE_NEEDED=true

    log_info "💾 Executing flush across indices to commit translogs..."
    # Note: Modern OpenSearch/Wazuh Indexer uses /_flush (/_flush/synced was deprecated & removed)
    api_call "POST" "/_flush"

    log_info "⏹️ Stopping Wazuh Indexer service..."
    systemctl stop wazuh-indexer

    update_package "wazuh-indexer"

    log_info "🔄 Reloading systemd and restarting Wazuh Indexer..."
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer

    log_info "⏳ Waiting for Indexer service and API to become responsive..."
    local max_retries=18
    local ready=false
    for ((i=1; i<=max_retries; i++)); do
        local code
        code=$(curl "${CURL_OPTS[@]}" --config "$CURL_CFG" -s -o /dev/null -w "%{http_code}" -X GET "https://${WAZUH_INDEXER_IP}:9200/" || echo "000")
        if [[ "$code" == "200" ]]; then
            ready=true
            break
        fi
        log_info "  Waiting for indexer heartbeat... (Attempt $i/$max_retries)"
        sleep 5
    done

    if [[ "$ready" != "true" ]]; then
        log_error "🛑 Wazuh Indexer did not become responsive after restart! Check /var/log/wazuh-indexer."
        exit 1
    fi
    log_success "Indexer API is online and responding."

    log_info "🔓 Re-enabling indexer shard routing allocation to 'all'..."
    api_call "PUT" "/_cluster/settings" '{"persistent": {"cluster.routing.allocation.enable": "all"}}'
    ALLOCATION_RESTORE_NEEDED=false
    log_success "Wazuh Indexer successfully upgraded."
}

upgrade_manager() {
    log_info "=================================================================="
    log_info "2️⃣ Upgrading Wazuh Manager & Server..."
    log_info "=================================================================="
    log_info "⏹️ Stopping wazuh-manager for upgrade..."
    systemctl stop wazuh-manager

    update_package "wazuh-manager"

    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager

    sleep 5
    if ! systemctl is-active --quiet wazuh-manager; then
        log_error "🛑 wazuh-manager failed to start after upgrade. Check ossec.log."
        exit 1
    fi
    log_success "Wazuh Manager successfully upgraded and running."
}

upgrade_filebeat() {
    log_info "=================================================================="
    log_info "3️⃣ Upgrading Filebeat & Loading Ingest Assets..."
    log_info "=================================================================="
    systemctl stop filebeat || true

    update_package "filebeat"

    log_info "📥 Downloading Filebeat module (v${FB_MOD_VER})..."
    local tmp_tar
    tmp_tar=$(mktemp /tmp/wazuh_filebeat_XXXXXX.tar.gz)
    if curl -sSfL "$FILEBEAT_MODULE_URL" -o "$tmp_tar"; then
        tar -xvz -C /usr/share/filebeat/module -f "$tmp_tar" >> "$LOG_FILE" 2>&1
        rm -f "$tmp_tar"
    else
        rm -f "$tmp_tar"
        log_error "🛑 Failed to download or unpack Filebeat module from: $FILEBEAT_MODULE_URL"
        exit 1
    fi

    log_info "📥 Downloading Elasticsearch/Indexer template for v$TARGET_VERSION..."
    if [[ -f /etc/filebeat/wazuh-template.json ]]; then
        cp /etc/filebeat/wazuh-template.json /etc/filebeat/wazuh-template.json.bak
    fi

    if curl -sSfL "$TEMPLATE_URL" -o /etc/filebeat/wazuh-template.json; then
        chmod go+r /etc/filebeat/wazuh-template.json
        rm -f /etc/filebeat/wazuh-template.json.bak
    else
        log_error "🛑 Failed to download wazuh-template.json from: $TEMPLATE_URL"
        if [[ -f /etc/filebeat/wazuh-template.json.bak ]]; then
            mv /etc/filebeat/wazuh-template.json.bak /etc/filebeat/wazuh-template.json
        fi
        exit 1
    fi

    systemctl daemon-reload
    systemctl enable filebeat
    systemctl restart filebeat

    log_info "🛠️ Running Filebeat setup protocols..."
    log_info "  Loading Ingest pipelines into Indexer..."
    filebeat setup --pipelines >> "$LOG_FILE" 2>&1 || log_warn "⚠️ Filebeat setup --pipelines finished with warnings (see $LOG_FILE)"

    log_info "  Loading Index management template..."
    filebeat setup --index-management -E output.logstash.enabled=false >> "$LOG_FILE" 2>&1 || log_warn "⚠️ Filebeat setup --index-management finished with warnings (see $LOG_FILE)"

    systemctl restart filebeat
    log_success "Filebeat upgraded and initialized."
}

upgrade_dashboard() {
    log_info "=================================================================="
    log_info "4️⃣ Upgrading Wazuh Dashboard..."
    log_info "=================================================================="
    systemctl stop wazuh-dashboard || true

    update_package "wazuh-dashboard"

    systemctl daemon-reload
    systemctl enable wazuh-dashboard
    systemctl start wazuh-dashboard

    log_info "⏳ Waiting for Wazuh Dashboard to start..."
    sleep 5
    if ! systemctl is-active --quiet wazuh-dashboard; then
        log_error "🛑 wazuh-dashboard failed to start. Check /usr/share/wazuh-dashboard/data/wazuh/logs."
        exit 1
    fi
    log_success "Wazuh Dashboard successfully upgraded."
}

# --- 14. Post-Flight Health Verification ---
run_postflight_verification() {
    log_info "=================================================================="
    log_info "🔍 Executing Post-Flight Health Validation..."
    log_info "=================================================================="

    local services=(wazuh-indexer wazuh-manager filebeat wazuh-dashboard)
    for s in "${services[@]}"; do
        if ! systemctl is-active --quiet "$s"; then
            log_error "🛑 Service '$s' is NOT active! Check 'systemctl status $s' and journalctl."
            exit 1
        else
            log_success "Service '$s' is ONLINE and active."
        fi
    done

    log_info "🩺 Checking Indexer cluster structural health..."
    local health
    health=$(curl "${CURL_OPTS[@]}" --config "$CURL_CFG" -sS -X GET "https://${WAZUH_INDEXER_IP}:9200/_cluster/health" 2>/dev/null | grep -Po '(?<="status":")[^"]*' || echo "unknown")

    if [[ "$health" == "green" ]]; then
        log_success "Cluster health is GREEN (all primary and replica shards allocated)."
    elif [[ "$health" == "yellow" ]]; then
        log_info "💛 Cluster health is YELLOW."
        log_info "   (Note: For All-in-One single-node clusters, YELLOW is expected and fully healthy because replica shards cannot be assigned to another node)."
    elif [[ "$health" == "red" ]]; then
        log_error "🛑 Cluster health is RED! Some primary shards are unassigned. Please inspect indexer logs immediately."
    else
        log_warn "⚠️ Cluster health returned '$health'. Check status via API or dashboard."
    fi

    NEW_VERSION=$(detect_current_version)
    log_success "Wazuh central components upgrade completed! Active Version: v${NEW_VERSION:-$TARGET_VERSION}"
}

# --- 15. Agent Upgrade Management ---
manage_agents_upgrade() {
    local upgrade_bin="/var/ossec/bin/agent_upgrade"
    if [[ ! -x "$upgrade_bin" ]]; then
        log_warn "⚠️ Agent upgrade binary not found at $upgrade_bin. Skipping agent upgrades."
        return 0
    fi

    local outdated_agents
    outdated_agents=$("$upgrade_bin" -l 2>/dev/null | awk '/^[0-9]+/ {print $1}' || true)

    if [[ -z "$outdated_agents" ]]; then
        log_info "🤷 No outdated connected agents found in the registry."
        return 0
    fi

    local agent_count
    agent_count=$(echo "$outdated_agents" | wc -w)
    log_info "Found $agent_count outdated connected agent(s) ready for upgrade."

    local execute_agents=false

    if [[ "$AUTO_UPGRADE_AGENTS" == "true" ]]; then
        execute_agents=true
    elif [[ "$SKIP_AGENTS" == "true" ]]; then
        log_info "⏭️ Skipping agent upgrades (--skip-agents requested)."
        return 0
    elif [[ "$NON_INTERACTIVE" == "true" || ! -t 0 ]]; then
        log_info "⏭️ Non-interactive mode active without --upgrade-agents. Skipping agent upgrades."
        return 0
    else
        echo ""
        read -r -p "🤔 Do you want to remotely upgrade all $agent_count outdated Wazuh agents now? (Y/n): " answer
        if [[ "$answer" =~ ^[Yy] ]] || [[ -z "$answer" ]]; then
            execute_agents=true
        else
            log_info "⏭️ Skipping agent upgrades."
            return 0
        fi
    fi

    if [[ "$execute_agents" == "true" ]]; then
        log_info "🤖 Dispatching remote agent upgrades..."
        local success_count=0
        local fail_count=0

        for agent_id in $outdated_agents; do
            log_info "  ⬆️ Dispatched upgrade for Agent ID: $agent_id"
            if "$upgrade_bin" -a "$agent_id" >> "$LOG_FILE" 2>&1; then
                ((success_count++)) || true
            else
                log_warn "  ⚠️ Upgrade dispatch failed for agent $agent_id (see $LOG_FILE)"
                ((fail_count++)) || true
            fi
        done
        log_success "Agent upgrades dispatch complete ($success_count succeeded, $fail_count failed)."
    fi
}

# --- Main Execution Flow ---
main() {
    parse_arguments "$@"
    print_banner
    check_prerequisites
    load_credentials
    resolve_versions_and_assets
    run_preflight_checks

    if [[ "$DRY_RUN" == "true" ]]; then
        echo ""
        log_success "🏁 DRY RUN COMPLETE: All pre-flight, network, credential, and version checks passed successfully!"
        log_info "No system changes or package upgrades were performed."
        exit 0
    fi

    UPGRADE_STARTED=true
    backup_configurations
    manage_package_hold "unhold"
    configure_repository

    # Sequencing: Indexer -> Manager -> Filebeat -> Dashboard
    upgrade_indexer
    upgrade_manager
    upgrade_filebeat
    upgrade_dashboard

    manage_package_hold "hold"
    run_postflight_verification
    manage_agents_upgrade

    echo ""
    log_success "🎉 Wazuh AIO Upgrade Process Successfully Finished!"
    log_info "Log file available at: $LOG_FILE"
}

main "$@"
