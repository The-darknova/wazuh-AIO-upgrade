# Wazuh All-in-One (AIO) Upgrade Script

This repository contains an automated Bash script (`wazuh_upgrade.sh`) designed to seamlessly upgrade a Wazuh All-in-One (AIO) architecture. It automates the complex sequencing required for upgrading Wazuh central components, including the Indexer, Manager, Dashboard, and Filebeat.

## Features

- **Automated Sequencing**: Follows the strict order required by Wazuh (Indexer -> Manager -> Filebeat -> Dashboard).
- **Dynamic Version Resolution**: Automatically queries the GitHub API for the latest Wazuh release if no target version is provided.
- **Secure Handling**: Extracts credentials securely via a `wazuh_creds` file to prevent leaking secrets into shell histories or process lists.
- **Cross-Distribution Support**: Works with `apt` (Debian/Ubuntu) and `yum` (RHEL/CentOS/AlmaLinux/Rocky).
- **Pre-flight & Post-flight Checks**: Ensures the environment is healthy (e.g. at least 5GB free disk space, services are running) before and after the operations.
- **Agent Rollout**: Includes an optional, interactive prompt to upgrade all connected Wazuh agents sequentially.

## Prerequisites

- **OS Environment**: A Debian-based (`apt`) or RHEL-based (`yum`) Linux distribution.
- **Root Privileges**: The script must be run as `root` (or via `sudo`).
- **Wazuh State**: The `wazuh-manager` service must be active and running before initiating the upgrade.
- **Disk Space**: At least 5GB of free space on the root (`/`) file system.

## Setup

Before running the script, you must configure your Wazuh administrative credentials.

1. Create or edit the `wazuh_creds` file in the same directory as the script.
2. Populate the file with your active details. It must contain the following variables:

```bash
WAZUH_INDEXER_IP=127.0.0.1
WAZUH_USER=admin
WAZUH_PASS=YourSuperSecretPassword
```

> **Note:** If executing against a non-local indexer, secure CA validation is enforced. Make sure the CA certificate is located at `/etc/wazuh-indexer/certs/root-ca.pem`.

## Usage

Make sure the script is executable:

```bash
chmod +x wazuh_upgrade.sh
```

Execute the script as `root`. You can either let the script automatically detect and use the latest Wazuh release, or specify a particular target version.

### Auto-Detect Latest Version

```bash
sudo ./wazuh_upgrade.sh
```

### Specify a Explicit Version

You can pass a specific version (with or without a leading `v`):

```bash
sudo ./wazuh_upgrade.sh 4.8.0
```
*(Or `sudo ./wazuh_upgrade.sh v4.8.0`)*

## Logs and Troubleshooting

All major steps and errors are logged locally. If an upgrade fails or gets stuck, check the output of the log file:

```bash
cat /var/log/wazuh_upgrade.log
```

The script implements "fail-fast" logic by aborting immediately if a critical API call or service startup fails, keeping your cluster state coherent and providing explicit error messages.
