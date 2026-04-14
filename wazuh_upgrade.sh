#!/bin/bash
# ==============================================================================
# Wazuh All-in-One (AIO) Architecture Upgrade Script
# Automated upgrades for central components (Indexer, Manager, Dashboard, Filebeat).
# ==============================================================================

set -euo pipefail

LOG_FILE="/var/log/wazuh_upgrade.log"

cat << "EOF"

 __          __             _       _    _           _       _       
 \ \        / /            | |     | |  | |         | |     | |      
  \ \  /\  / /_ _ _____   _| |__   | |  | |_ __   __| | __ _| |_ ___ 
   \ \/  \/ / _` |_  / | | | '_ \  | |  | | '_ \ / _` |/ _` | __/ _ \
    \  /\  / (_| |/ /| |_| | | | | | |__| | |_) | (_| | (_| | ||  __/
     \/  \/ \__,_/___|\__,_|_| |_|  \____/| .__/ \__,_|\__,_|\__\___|
                                          | |
     All-in-One Upgrade Script            |_|
==============================================================================
EOF

# --- 1. Centralized Logging ---
log_info() {
    local msg="$1"
    echo -e "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $msg" | tee -a "$LOG_FILE"
}

log_error() {
    local msg="$1"
    echo -e "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $msg" >&2
    echo -e "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE"
}

# --- 2. Privilege Check ---
if [[ "$EUID" -ne 0 ]]; then
    log_error "🛑 This script must be run as root."
    exit 1
fi

log_info "✨ Starting Wazuh AIO Upgrade Process..."

# --- 3. Dynamic Versioning ---
if [[ -z "${1:-}" ]]; then
    log_info "🔍 No target version provided. Querying GitHub API for latest Wazuh release..."
    LATEST_TAG=$(curl -sS "https://api.github.com/repos/wazuh/wazuh/releases/latest" | grep -Po '(?<="tag_name": "v)[^"]*')
    if [[ -z "$LATEST_TAG" ]]; then
        log_error "🛑 Failed to retrieve the latest stable version of Wazuh. Please provide it manually."
        exit 1
    fi
    TARGET_VERSION="$LATEST_TAG"
    log_info "🎯 Dynamically resolved target version to: $TARGET_VERSION"
else
    # Strip leading 'v' if provided
    TARGET_VERSION="${1#v}"
    log_info "🎯 User provided target version: $TARGET_VERSION"
fi

if [[ "$TARGET_VERSION" =~ ^4\.[0-7]\. ]]; then
    FB_MOD_VER="0.3"
else
    FB_MOD_VER="0.4"
fi

TEMPLATE_URL="https://raw.githubusercontent.com/wazuh/wazuh/v${TARGET_VERSION}/extensions/elasticsearch/7.x/wazuh-template.json"
FILEBEAT_MODULE_URL="https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-${FB_MOD_VER}.tar.gz"

log_info "🌐 Download URLs configured:"
log_info "  📄 Elasticsearch Template: $TEMPLATE_URL"
log_info "  📦 Filebeat Module: $FILEBEAT_MODULE_URL"

# --- 4. Identify the OS structure for Package Management ---
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_FAMILY="${ID_LIKE:-$ID}"
else
    log_error "🛑 Cannot determine OS. /etc/os-release not found."
    exit 1
fi

configure_repo() {
    if echo "$OS_FAMILY" | grep -qi -e 'debian' -e 'ubuntu'; then
        log_info "🐧 Detected Debian-based OS. Configuring APT repositories."
        PKG_MANAGER="apt-get"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y apt-transport-https curl gnupg
        curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update
    elif echo "$OS_FAMILY" | grep -qi -e 'rhel' -e 'centos' -e 'fedora' -e 'almalinux' -e 'rocky'; then
        log_info "🔴 Detected RHEL-based OS. Configuring YUM/DNF repositories."
        PKG_MANAGER="yum"
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    else
        log_error "🛑 Unsupported OS family: $OS_FAMILY"
        exit 1
    fi
}

update_package() {
    local PKG="$1"
    log_info "📦 Upgrading package: $PKG to latest matched version in repo..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        apt-get install -y --only-upgrade "$PKG"
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum upgrade -y "$PKG"
    fi
}

# --- 5. Security & Credentials Strategy ---
CREDS_FILE="wazuh_creds"
if [[ ! -f "$CREDS_FILE" ]]; then
    log_error "🛑 Credentials file not found at $CREDS_FILE."
    log_error "  To securely pass credentials, create this file containing:"
    log_error "  WAZUH_INDEXER_IP=127.0.0.1"
    log_error "  WAZUH_USER=admin"
    log_error "  WAZUH_PASS=SecretPassword"
    exit 1
fi

# Load credentials securely without prompting to bash history or memory dumping via read
source "$CREDS_FILE"

if [[ -z "${WAZUH_INDEXER_IP:-}" || -z "${WAZUH_USER:-}" || -z "${WAZUH_PASS:-}" ]]; then
    log_error "🛑 Missing required variables in $CREDS_FILE (WAZUH_INDEXER_IP, WAZUH_USER, WAZUH_PASS)"
    exit 1
fi

# --- 6. API Interaction & Safe Self-Signed fallback ---
WAZUH_CACERT="/etc/wazuh-indexer/certs/root-ca.pem"
CURL_OPTS=(-sS)

if [[ ! -f "$WAZUH_CACERT" ]]; then
    log_info "⚠️ CA certificate not found at $WAZUH_CACERT. Falling back to insecure mode."
    # Strict validation to prevent MITM on public networks with -k 
    if [[ "$WAZUH_INDEXER_IP" != "127.0.0.1" && "$WAZUH_INDEXER_IP" != "localhost" && "$WAZUH_INDEXER_IP" != "::1" ]]; then
        log_error "🛑 Insecure curl (-k) is ONLY permitted for localhost. Target IP: $WAZUH_INDEXER_IP is potentially exposed."
        log_error "  Please point to a local IP or ensure the CA certificate is available to proceed."
        exit 1
    fi
    CURL_OPTS+=("-k")
else
    log_info "🔒 Using CA certificate $WAZUH_CACERT for strict SSL validation."
    CURL_OPTS+=("--cacert" "$WAZUH_CACERT")
fi

api_call() {
    local METHOD="$1"
    local ENDPOINT="$2"
    local DATA="${3:-}"

    local CMD=(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" -X "$METHOD" "https://${WAZUH_INDEXER_IP}:9200${ENDPOINT}" -u "$WAZUH_USER:$WAZUH_PASS")
    
    if [[ -n "$DATA" ]]; then
        CMD+=(-H "Content-Type: application/json" -d "$DATA")
    fi

    local HTTP_CODE
    HTTP_CODE=$("${CMD[@]}")
    if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -gt 299 ]]; then
        log_error "🛑 API call to $ENDPOINT failed with HTTP code $HTTP_CODE"
        exit 1
    fi
}

# --- 7. Upgrade Sequence ---

# PRE-FLIGHT
log_info "🛫 Executing Pre-flight Checks..."
FREE_SPACE=$(df -m / | awk 'NR==2 {print $4}')
if [[ "$FREE_SPACE" -lt 5120 ]]; then
    log_error "🛑 Less than 5GB of disk space available. Aborting upgrade to protect database integrity."
    exit 1
fi

if ! systemctl is-active --quiet wazuh-manager; then
    log_error "🛑 wazuh-manager is not running! Ensure environment is healthy before upgrading."
    exit 1
fi

configure_repo

# STOP SERVICES
log_info "⏸️ Stopping Filebeat and Wazuh Dashboard logic..."
systemctl stop filebeat || true
systemctl stop wazuh-dashboard || true

# UPGRADE WAZUH-INDEXER
log_info "1️⃣ Disabling routing allocation on logic tier..."
api_call "PUT" "/_cluster/settings" '{"persistent": {"cluster.routing.allocation.enable": "primaries"}}'

log_info "2️⃣ Executing synced flush across logical indices..."
api_call "POST" "/_flush/synced"

log_info "3️⃣ Upgrading Wazuh Indexer core package..."
systemctl stop wazuh-indexer
update_package "wazuh-indexer"

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

# Wait for indexer to be ready before enabling allocation
log_info "⏳ Waiting for Indexer API to synchronize and activate..."
sleep 15
MAX_RETRIES=10
for ((i=1; i<=MAX_RETRIES; i++)); do
    HTTP_CODE=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" -X GET "https://${WAZUH_INDEXER_IP}:9200/" -u "$WAZUH_USER:$WAZUH_PASS" || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        break
    fi
    log_info "💓 Waiting for indexer heartbeat... ($i/$MAX_RETRIES)"
    sleep 5
    if [[ "$i" -eq "$MAX_RETRIES" ]]; then
        log_error "🛑 Wazuh Indexer did not come online in time! Reverting or manual inspection needed."
        exit 1
    fi
done

log_info "4️⃣ Re-enabling indexer routing allocation..."
api_call "PUT" "/_cluster/settings" '{"persistent": {"cluster.routing.allocation.enable": "all"}}'

# UPGRADE WAZUH-MANAGER
log_info "🔄 Upgrading Wazuh Manager backend..."
update_package "wazuh-manager"

# UPGRADE FILEBEAT & CONFIG
log_info "🚀 Upgrading Filebeat Forwarder..."
update_package "filebeat"

log_info "⚙️ Applying dynamic Filebeat configurations for v$TARGET_VERSION..."
curl -sS "$FILEBEAT_MODULE_URL" | tar -xvz -C /usr/share/filebeat/module
curl -sS -o /etc/filebeat/wazuh-template.json "$TEMPLATE_URL"
chmod go+r /etc/filebeat/wazuh-template.json

systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
log_info "🛠️ Running Filebeat setup protocol..."
filebeat setup --index-management -E output.logstash.enabled=false

# UPGRADE WAZUH-DASHBOARD
log_info "📈 Upgrading Wazuh Dashboard frontend..."
update_package "wazuh-dashboard"
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# POST-FLIGHT VERIFICATION
log_info "✅ Executing Post-flight Validation..."
SERVICES=(wazuh-indexer wazuh-manager filebeat wazuh-dashboard)
for s in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$s"; then
        log_error "🛑 Service $s failed to resume! Please check journalctl."
        exit 1
    else
         log_info "🟢 Service $s is ONLINE."
    fi
done

log_info "🩺 Validating Elasticsearch/Indexer cluster structural health..."
HEALTH=$(curl "${CURL_OPTS[@]}" -sS -X GET "https://${WAZUH_INDEXER_IP}:9200/_cluster/health" -u "$WAZUH_USER:$WAZUH_PASS" | grep -Po '(?<="status":")[^"]*' || echo "unknown")
if [[ "$HEALTH" != "green" ]]; then
    log_info "⚠️ Warning: Cluster health is '$HEALTH' (not green). This may take time to normalize."
else
    log_info "💚 Cluster health is fully GREEN and verified."
fi

log_info "🎉 AIO Components Upgrade Successfully Completed!"

# AGENT UPGRADE (Optional)
echo
read -p "🤔 Do you want to remotely upgrade all connected Wazuh agents now? (Y/n): " UPGRADE_AGENTS
if [[ "$UPGRADE_AGENTS" =~ ^[Yy] ]] || [[ -z "$UPGRADE_AGENTS" ]]; then
    log_info "🤖 Initiating fleet-wide agent upgrades..."
    if [[ -x /var/ossec/bin/agent_upgrade ]]; then
        AGENTS=$(/var/ossec/bin/agent_upgrade -l | awk '/^[0-9]+/ {print $1}')
        if [[ -z "$AGENTS" ]]; then
            log_info "🤷 No connected agents found in the registry to upgrade."
        else
            for id in $AGENTS; do
                log_info "⬆️ Upgrading endpoint ID: $id"
                /var/ossec/bin/agent_upgrade -a "$id" || log_error "🛑 Failed to upgrade agent $id"
            done
            log_info "🏁 Agent upgrades fully dispatched."
        fi
    else
        log_error "🛑 Agent upgrade binary is not available. Skipping agent upgrades."
    fi
else
    log_info "⏭️ Skipping agent rollout."
fi

exit 0
