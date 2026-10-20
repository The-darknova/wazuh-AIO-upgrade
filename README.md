# Wazuh All-in-One (AIO) Upgrade Script

This repository contains an automated, enterprise-grade Bash script (`wazuh_upgrade.sh`) designed to seamlessly upgrade a Wazuh All-in-One (AIO) architecture. It automates the complex sequencing required for upgrading Wazuh central components, including the Wazuh Indexer, Wazuh Manager, Filebeat (with ingest pipelines & templates), and Wazuh Dashboard.

---

## Key Features & Enhancements

- **Strict Component Sequencing**: Adheres to the official Wazuh upgrade order:
  $$\text{Wazuh Indexer} \longrightarrow \text{Wazuh Manager} \longrightarrow \text{Filebeat} \longrightarrow \text{Wazuh Dashboard} \longrightarrow \text{Wazuh Agents}$$
- **Automatic Configuration & Key Backup**: Automatically packages `/var/ossec/etc/` (including `client.keys`, custom decoders, and rules), `/etc/wazuh-indexer/`, `/etc/wazuh-dashboard/`, and `/etc/filebeat/` into a timestamped, permission-secured archive (`/var/backups/wazuh/wazuh_backup_<timestamp>.tar.gz`, mode `0600`).
- **Resilient Trap & Rollback Protection**: If an upgrade is interrupted or aborted midway, the script's `EXIT`/`INT`/`TERM` trap automatically re-enables indexer shard routing allocation (`cluster.routing.allocation.enable: all`) and restores package holds, preventing cluster state corruption.
- **Credential & Process Security**: Passwords are supplied to `curl` using temporary, permission-locked configuration files rather than CLI arguments, preventing credential exposure in `ps aux` or `/proc/*/cmdline`.
- **Dynamic Version Resolution**: Automatically queries the GitHub API for the latest stable Wazuh release if no target version is provided, and maps compatible Filebeat modules (`v0.3`, `v0.4`, or `v0.5`).
- **Package Hold & Pinning Management**: Automatically detects, unholds, upgrades to the target version, and re-holds `apt-mark` or `yum versionlock` packages.
- **Config Preservation**: Uses `-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"` on Debian/Ubuntu to prevent package managers from overwriting custom configurations, certificates, and passwords.
- **Non-Interactive & CI/CD Support**: Full command-line flag support (`--yes`, `--upgrade-agents`, `--skip-backup`, `--dry-run`) enables hands-free execution in Ansible, cron, or CI/CD pipelines.
- **Accurate Cluster Health Validation**: Understands that `yellow` status is normal and healthy for single-node All-in-One deployments (due to unassigned replica shards), preventing unnecessary operator alarm.

---

## Prerequisites

- **Operating System**: Debian / Ubuntu (`apt`) or RHEL / CentOS / AlmaLinux / Rocky Linux / Fedora (`yum` / `dnf`).
- **Root Privileges**: The script must be run as `root` (or with `sudo`).
- **Wazuh Health**: `wazuh-indexer` and `wazuh-manager` must be active and accessible before starting the upgrade.
- **Disk Space**: At least 5GB of free space on both `/` and `/var` partitions.

---

## Setup & Credentials

Before executing the script, configure your Wazuh administrative credentials in a dedicated credentials file:

1. Create or edit `wazuh_creds` in the script directory (or pass via `--creds <path>`):
   ```bash
   WAZUH_INDEXER_IP=127.0.0.1
   WAZUH_USER=admin
   WAZUH_PASS=YourSuperSecretPassword
   ```

2. Restrict file permissions to root only:
   ```bash
   chmod 600 wazuh_creds
   ```
   *(The script will also automatically enforce `0600` if loose permissions are detected).*

> **Note:** If querying a remote or non-loopback indexer, strict TLS verification is enforced. Ensure your root CA certificate is available at `/etc/wazuh-indexer/certs/root-ca.pem`.

---

## Usage

Ensure the script is marked executable:

```bash
chmod +x wazuh_upgrade.sh
```

### 1. Dry Run / Pre-flight Verification (Recommended)

Run pre-flight checks, credential validation, disk space checks, and asset reachability tests without changing any system state:

```bash
sudo ./wazuh_upgrade.sh --dry-run
```

### 2. Auto-Detect and Upgrade to Latest Version

Queries the latest release from GitHub and executes the upgrade interactively:

```bash
sudo ./wazuh_upgrade.sh
```

### 3. Upgrade to an Explicit Version

Specify the target version as an argument or via `-t` / `--target-version`:

```bash
sudo ./wazuh_upgrade.sh 4.8.0
# or
sudo ./wazuh_upgrade.sh -t 4.8.0
```

### 4. Fully Automated / Non-Interactive Execution (e.g. Ansible / CI)

Run without interactive prompts and automatically dispatch agent upgrades:

```bash
sudo ./wazuh_upgrade.sh -t 4.8.0 --yes --upgrade-agents
```

### CLI Options Reference

| Option | Description |
| :--- | :--- |
| `TARGET_VERSION` | Positional target version string (e.g., `4.8.0` or `v4.8.0`). |
| `-t, --target-version <v>` | Explicit target version to upgrade to. |
| `-c, --creds <path>` | Custom path to the credentials file (default: `./wazuh_creds`). |
| `-y, --yes, --non-interactive` | Run non-interactively without prompt confirmation. |
| `--dry-run` | Run all validation, network, and pre-flight checks without modifying the system. |
| `--skip-backup` | Skip creating the `/var/backups/wazuh/` configuration archive. |
| `--skip-agents` | Skip remote agent upgrades without prompting. |
| `--upgrade-agents` | Automatically dispatch remote upgrades to all connected outdated agents. |
| `-f, --force` | Force re-installation even if the installed version matches the target version. |
| `-h, --help` | Display command help and usage examples. |

---

## Upgraded Architecture Workflow

```
[ Pre-Flight Checks & Version Resolution ]
                   │
[ Backup Configurations & Keys to /var/backups/wazuh/ ]
                   │
[ Temporarily Unhold Packages (apt-mark / versionlock) ]
                   │
[ Configure Official Wazuh Package Repositories ]
                   │
[ 1. Wazuh Indexer ] ── Disable routing allocation ("primaries")
                     ── Execute _flush
                     ── Stop indexer & update package
                     ── Start indexer & poll health
                     ── Re-enable routing allocation ("all")
                   │
[ 2. Wazuh Manager ] ── Stop manager & update package
                     ── Restart service & verify active
                   │
[ 3. Filebeat ]     ── Update package
                     ── Deploy Wazuh filebeat module & template
                     ── Load ingest pipelines & index management
                     ── Restart filebeat
                   │
[ 4. Dashboard ]    ── Update wazuh-dashboard package
                     ── Restart dashboard & verify active
                   │
[ Restore Package Holds (apt-mark hold / versionlock add) ]
                   │
[ Post-Flight Verification & Cluster Health Check ]
                   │
[ Optional Remote Agent Fleet Upgrades ]
```

---

## Logs and Troubleshooting

All operations and detailed outputs are logged locally:

```bash
sudo tail -f /var/log/wazuh_upgrade.log
```

If an unexpected failure or interrupt occurs:
1. The cleanup trap will attempt to restore shard allocation back to `all`.
2. To check service statuses:
   ```bash
   sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard
   ```
3. To inspect your configuration backup:
   ```bash
   sudo ls -lh /var/backups/wazuh/
   ```
