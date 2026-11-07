#!/bin/bash

# WireGuard-Manager Installation Script
# Purpose: This script automates the installation of WireGuard-Manager, a comprehensive tool for managing WireGuard VPN configurations.
# Author: ComplexOrganizations
# Repository: https://github.com/complexorganizations/wireguard-manager

# Usage Instructions:
# 1. System Requirements: Ensure you have 'curl' installed on your system. This script is compatible with most Linux distributions.
# 2. Downloading the Script:
#    - Use the following command to download the script:
#      curl https://raw.githubusercontent.com/complexorganizations/wireguard-manager/main/wireguard-manager.sh --create-dirs -o /usr/local/bin/wireguard-manager.sh
# 3. Making the Script Executable:
#    - Grant execution permissions to the script:
#      chmod +x /usr/local/bin/wireguard-manager.sh
# 4. Running the Script:
#    - Execute the script with root privileges:
#      bash /usr/local/bin/wireguard-manager.sh
# 5. Follow the on-screen instructions to complete the installation of WireGuard-Manager.

# Advanced Usage:
# - The script supports various command-line arguments for custom installations. Refer to the repository's readme.md for more details.
# - For automated deployments, environment variables can be set before running this script.

# Troubleshooting:
# - If you encounter issues, ensure your system is up-to-date and retry the installation.
# - For specific errors, refer to the 'Troubleshooting' section in the repository's documentation.

# Contributing:
# - Contributions to the script are welcome. Please follow the contributing guidelines in the repository.

# Contact Information:
# - For support, feature requests, or bug reports, please open an issue on the GitHub repository.

# License: MIT License

# Note: This script is provided 'as is', without warranty of any kind. The user is responsible for understanding the operations and risks involved.

# Check if the script is running as root
function check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
  fi
}

# Call the function to check root privileges
check_root

# Cron runs with PATH=/usr/bin:/bin, which hides nft, cron, sysctl etc. in /usr/sbin.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Peer names are used in sed ranges, file names and cron lines: keep them simple.
function validate-peer-name() {
  if [[ ! "${1}" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "Error: Invalid peer name '${1}'. Use letters, digits, '-' and '_' only."
    exit 1
  fi
}

# Address checks used for public IP detection and DNS validation.
function is-ipv4() {
  local octet
  local -a octets
  [[ "${1}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -ra octets <<<"${1}"
  for octet in "${octets[@]}"; do
    ((10#${octet} <= 255)) || return 1
  done
}

function is-ipv6() {
  [[ "${1}" == *:* && "${1}" =~ ^[0-9A-Fa-f:.]+$ && ${#1} -le 45 ]]
}

# Private, CGNAT, loopback and link-local IPv4 ranges are not reachable from the internet.
function is-private-ipv4() {
  [[ "${1}" =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

# Suggest the next free default peer name: peer1, peer2, ...
function next-peer-name() {
  local n=1
  while grep --quiet "^# peer${n} start$" "${WIREGUARD_CONFIG}" 2>/dev/null || [ -e "${WIREGUARD_CLIENT_PATH}/peer${n}.conf" ]; do
    n=$((n + 1))
  done
  echo "peer${n}"
}

# Try each URL in order and print the first non-empty response to stdout.
function fetch-first() {
  local url body
  for url in "$@"; do
    if body=$(curl --fail --silent --location --retry 2 --connect-timeout 10 --max-time 120 "${url}") && [ -n "${body}" ]; then
      printf '%s\n' "${body}"
      return 0
    fi
    echo "Warning: ${url} failed, trying next source." >&2
  done
  return 1
}

# Refresh the Unbound root hints. Prefers the distro copy (Debian/Ubuntu dns-root-data), then downloads.
# Only accepts a file that actually lists the root servers. Returns 0 if the file changed.
function update-root-hints() {
  local tmp
  tmp=$(mktemp)
  if [ -s "${UNBOUND_LOCAL_ROOT_HINTS}" ]; then
    cp "${UNBOUND_LOCAL_ROOT_HINTS}" "${tmp}"
  elif ! fetch-first "${UNBOUND_ROOT_HINTS_URLS[@]}" >"${tmp}"; then
    rm --force "${tmp}"
    echo "Warning: Could not download root hints, keeping the existing file."
    return 1
  fi
  if ! grep --quiet --ignore-case "A.ROOT-SERVERS.NET" "${tmp}"; then
    rm --force "${tmp}"
    echo "Warning: Downloaded root hints look invalid, keeping the existing file."
    return 1
  fi
  if cmp --silent "${tmp}" "${UNBOUND_ROOT_HINTS}"; then
    rm --force "${tmp}"
    return 1
  fi
  mkdir --parents "$(dirname "${UNBOUND_ROOT_HINTS}")"
  chmod 644 "${tmp}"
  mv "${tmp}" "${UNBOUND_ROOT_HINTS}"
  return 0
}

# Refresh the content-blocker zone file. Accepts plain domain lists and hosts-format lists
# (0.0.0.0 example.com). Rolls back if Unbound rejects the result. Returns 0 if the file changed.
function update-content-blocker() {
  local raw tmp
  raw=$(mktemp)
  tmp=$(mktemp)
  if ! fetch-first "${UNBOUND_CONFIG_HOST_URLS[@]}" >"${raw}"; then
    rm --force "${raw}" "${tmp}"
    echo "Warning: Could not download the content-blocker list, keeping the existing one."
    return 1
  fi
  awk '{ d = $1 } ($1 == "0.0.0.0" || $1 == "127.0.0.1" || $1 == "::" || $1 == "::1") { d = $2 } d ~ /^[A-Za-z0-9._-]+$/ && d !~ /^#/ && d != "localhost" && !seen[d]++ { print "local-zone: \"" d "\" always_refuse" }' <"${raw}" >"${tmp}"
  rm --force "${raw}"
  if [ ! -s "${tmp}" ]; then
    rm --force "${tmp}"
    echo "Warning: Content-blocker list was empty or unreadable, keeping the existing one."
    return 1
  fi
  if cmp --silent "${tmp}" "${UNBOUND_CONFIG_HOST}"; then
    rm --force "${tmp}"
    return 1
  fi
  mkdir --parents "$(dirname "${UNBOUND_CONFIG_HOST}")"
  chmod 644 "${tmp}"
  if [ -f "${UNBOUND_CONFIG_HOST}" ]; then
    cp --preserve=all "${UNBOUND_CONFIG_HOST}" "${UNBOUND_CONFIG_HOST}.bak"
  fi
  mv "${tmp}" "${UNBOUND_CONFIG_HOST}"
  if [ -f "${UNBOUND_CONFIG}" ] && ! unbound-checkconf "${UNBOUND_CONFIG}" >/dev/null 2>&1; then
    if [ -f "${UNBOUND_CONFIG_HOST}.bak" ]; then
      mv "${UNBOUND_CONFIG_HOST}.bak" "${UNBOUND_CONFIG_HOST}"
    else
      : >"${UNBOUND_CONFIG_HOST}"
    fi
    echo "Warning: New content-blocker list broke the Unbound config, rolled back."
    return 1
  fi
  rm --force "${UNBOUND_CONFIG_HOST}.bak"
  return 0
}

# Function to gather current system details
function system-information() {
  # This function fetches the ID, version, and major version of the current system
  if [ -f /etc/os-release ]; then
    # If /etc/os-release file is present, source it to obtain system details
    # shellcheck source=/dev/null
    source /etc/os-release
    CURRENT_DISTRO=${ID}                                                                              # CURRENT_DISTRO holds the system's ID
    CURRENT_DISTRO_VERSION=${VERSION_ID}                                                              # CURRENT_DISTRO_VERSION holds the system's VERSION_ID
    CURRENT_DISTRO_MAJOR_VERSION=$(echo "${CURRENT_DISTRO_VERSION}" | cut --delimiter="." --fields=1) # CURRENT_DISTRO_MAJOR_VERSION holds the major version of the system (e.g., "16" for Ubuntu 16.04)
  fi
}

# Invoke the system-information function
system-information

# Define a function to check system requirements
function installing-system-requirements() {
  # Check if the current Linux distribution is supported
  if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ] || [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ] || [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ] || [ "${CURRENT_DISTRO}" == "alpine" ] || [ "${CURRENT_DISTRO}" == "freebsd" ] || [ "${CURRENT_DISTRO}" == "ol" ]; }; then
    # Check if required packages are already installed
    if { [ ! -x "$(command -v curl)" ] || [ ! -x "$(command -v cut)" ] || [ ! -x "$(command -v jq)" ] || [ ! -x "$(command -v ip)" ] || [ ! -x "$(command -v lsof)" ] || [ ! -x "$(command -v crontab)" ] || [ ! -x "$(command -v awk)" ] || [ ! -x "$(command -v ps)" ] || [ ! -x "$(command -v grep)" ] || [ ! -x "$(command -v qrencode)" ] || [ ! -x "$(command -v sed)" ] || [ ! -x "$(command -v zip)" ] || [ ! -x "$(command -v unzip)" ] || [ ! -x "$(command -v openssl)" ] || [ ! -x "$(command -v nft)" ] || [ ! -x "$(command -v chattr)" ] || [ ! -x "$(command -v gpg)" ] || [ ! -x "$(command -v systemd-detect-virt)" ]; }; then
      # Install required packages depending on the Linux distribution
      if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        apt-get update
        apt-get install curl coreutils jq iproute2 lsof cron gawk procps grep qrencode sed zip unzip openssl nftables ifupdown e2fsprogs gnupg systemd -y
      elif { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        yum check-update
        if [ "${CURRENT_DISTRO}" == "centos" ] && [ "${CURRENT_DISTRO_MAJOR_VERSION}" -ge 7 ]; then
          yum install epel-release elrepo-release -y
        fi
        if [ "${CURRENT_DISTRO}" == "centos" ] && [ "${CURRENT_DISTRO_MAJOR_VERSION}" == 7 ]; then
          yum install yum-plugin-elrepo -y
        fi
        yum install curl coreutils jq iproute lsof cronie gawk procps-ng grep qrencode sed zip unzip openssl nftables NetworkManager e2fsprogs gnupg systemd -y
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Sy --noconfirm archlinux-keyring
        pacman -Su --noconfirm --needed curl coreutils jq iproute2 lsof cronie gawk procps-ng grep qrencode sed zip unzip openssl nftables ifupdown e2fsprogs gnupg systemd
      elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
        apk update
        apk add curl coreutils jq iproute2 lsof cronie gawk procps grep sed zip unzip openssl nftables e2fsprogs gnupg
        # apk add curl coreutils jq iproute2 lsof cronie gawk procps grep qrencode sed zip unzip openssl nftables ifupdown e2fsprogs gnupg systemd
      elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
        pkg update
        pkg install curl coreutils jq iproute2 lsof cronie gawk procps grep qrencode sed zip unzip openssl nftables ifupdown e2fsprogs gnupg systemd
      elif [ "${CURRENT_DISTRO}" == "ol" ]; then
        yum check-update
        yum install curl coreutils jq iproute lsof cronie gawk procps-ng grep qrencode sed zip unzip openssl nftables NetworkManager e2fsprogs gnupg systemd -y
      fi
    fi
  else
    echo "Error: Your current distribution ${CURRENT_DISTRO} version ${CURRENT_DISTRO_VERSION} is not supported by this script. Please consider updating your distribution or using a supported one."
    exit
  fi
}

# Call the function to check for system requirements and install necessary packages if needed
installing-system-requirements

# Checking For Virtualization
function virt-check() {
  # This code checks if the system is running in a supported virtualization.
  # It returns the name of the virtualization if it is supported, or "none" if
  # it is not supported. This code is used to check if the system is running in
  # a virtual machine, and if so, if it is running in a supported virtualization.
  # systemd-detect-virt is a utility that detects the type of virtualization
  # that the system is running on. It returns a string that indicates the name
  # of the virtualization, such as "kvm" or "vmware".
  CURRENT_SYSTEM_VIRTUALIZATION=$(systemd-detect-virt)
  # This case statement checks if the virtualization that the system is running
  # on is supported. If it is not supported, the script will print an error
  # message and exit.
  case ${CURRENT_SYSTEM_VIRTUALIZATION} in
  "kvm" | "none" | "qemu" | "lxc" | "microsoft" | "vmware" | "xen" | "amazon" | "docker") ;;
  *)
    echo "Error: the ${CURRENT_SYSTEM_VIRTUALIZATION} virtualization is currently not supported. Please stay tuned for future updates."
    exit
    ;;
  esac
}

# Call the virt-check function to check for supported virtualization.
virt-check

# The following function checks the kernel version.
function kernel-check() {
  CURRENT_KERNEL_VERSION=$(uname --kernel-release | cut --delimiter="." --fields=1-2)
  # Get the current kernel version and extract the major and minor version numbers.
  CURRENT_KERNEL_MAJOR_VERSION=$(echo "${CURRENT_KERNEL_VERSION}" | cut --delimiter="." --fields=1)
  # Extract the major version number from the current kernel version.
  CURRENT_KERNEL_MINOR_VERSION=$(echo "${CURRENT_KERNEL_VERSION}" | cut --delimiter="." --fields=2)
  # Extract the minor version number from the current kernel version.
  ALLOWED_KERNEL_VERSION="3.1"
  # Set the minimum allowed kernel version to 3.1.0.
  ALLOWED_KERNEL_MAJOR_VERSION=$(echo ${ALLOWED_KERNEL_VERSION} | cut --delimiter="." --fields=1)
  # Extract the major version number from the allowed kernel version.
  ALLOWED_KERNEL_MINOR_VERSION=$(echo ${ALLOWED_KERNEL_VERSION} | cut --delimiter="." --fields=2)
  # Extract the minor version number from the allowed kernel version.
  if [ "${CURRENT_KERNEL_MAJOR_VERSION}" -lt "${ALLOWED_KERNEL_MAJOR_VERSION}" ]; then
    # If the current major version is less than the allowed major version, show an error message and exit.
    echo "Error: Your current kernel version ${CURRENT_KERNEL_VERSION} is not supported. Please update to version ${ALLOWED_KERNEL_VERSION} or later."
    exit
  fi
  if [ "${CURRENT_KERNEL_MAJOR_VERSION}" == "${ALLOWED_KERNEL_MAJOR_VERSION}" ]; then
    # If the current major version is equal to the allowed major version, check the minor version.
    if [ "${CURRENT_KERNEL_MINOR_VERSION}" -lt "${ALLOWED_KERNEL_MINOR_VERSION}" ]; then
      # If the current minor version is less than the allowed minor version, show an error message and exit.
      echo "Error: Your current kernel version ${CURRENT_KERNEL_VERSION} is not supported. Please update to version ${ALLOWED_KERNEL_VERSION} or later."
      exit
    fi
  fi
}

# Call the kernel-check function to verify the kernel version.
kernel-check

# The following function checks if the current init system is one of the allowed options.
function check-current-init-system() {
  # This function checks if the current init system is systemd or sysvinit.
  # If it is neither, the script exits.
  CURRENT_INIT_SYSTEM=$(ps --no-headers -o comm 1)
  # This line retrieves the current init system by checking the process name of PID 1.
  case ${CURRENT_INIT_SYSTEM} in
  # The case statement checks if the retrieved init system is one of the allowed options.
  *"systemd"* | *"init"* | *"bash"* | *"sh"*)
    # If the init system is systemd or sysvinit (init), continue with the script.
    ;;
  *)
    # If the init system is not one of the allowed options, display an error message and exit.
    echo "Error: The ${CURRENT_INIT_SYSTEM} initialization system is currently not supported. Please stay tuned for future updates."
    exit
    ;;
  esac
}

# The check-current-init-system function is being called.

check-current-init-system
# Calls the check-current-init-system function.

# The following function checks if there's enough disk space to proceed with the installation.
function check-disk-space() {
  # This function checks if there is more than 1 GB of free space on the drive.
  FREE_SPACE_ON_DRIVE_IN_MB=$(df -m / | tr --squeeze-repeats " " | tail -n1 | cut --delimiter=" " --fields=4)
  # This line calculates the available free space on the root partition in MB.
  if [ "${FREE_SPACE_ON_DRIVE_IN_MB}" -le 1024 ]; then
    # If the available free space is less than or equal to 1024 MB (1 GB), display an error message and exit.
    echo "Error: You need more than 1 GB of free space to install everything. Please free up some space and try again."
    exit
  fi
}

# The check-disk-space function is being called.

check-disk-space
# Calls the check-disk-space function.

# Global variables
# Assigns the path of the current script to a variable
CURRENT_FILE_PATH=$(realpath "${0}")
# Assigns the WireGuard website URL to a variable
WIREGUARD_WEBSITE_URL="https://www.wireguard.com"
# Assigns a path for WireGuard
WIREGUARD_PATH="/etc/wireguard"
# Assigns a path for WireGuard clients
# Client configs are named <peer>.conf; a non-default interface gets its own folder so names can't collide
if [ "${WIREGUARD_PUB_NIC}" == "wg0" ]; then
  WIREGUARD_CLIENT_PATH="${WIREGUARD_PATH}/clients"
else
  WIREGUARD_CLIENT_PATH="${WIREGUARD_PATH}/clients-${WIREGUARD_PUB_NIC}"
fi
# Assigns a public network interface name for WireGuard
WIREGUARD_PUB_NIC="${WIREGUARD_PUB_NIC:-wg0}"
# Assigns a path for the WireGuard configuration file
WIREGUARD_CONFIG="${WIREGUARD_PATH}/${WIREGUARD_PUB_NIC}.conf"
# Assigns a path for the WireGuard additional peer configuration file
WIREGUARD_ADD_PEER_CONFIG="${WIREGUARD_PATH}/${WIREGUARD_PUB_NIC}-add-peer.conf"
# Sysctl drop-in that keeps IP forwarding enabled for the tunnel
WIREGUARD_SYSCTL_CONFIG="/etc/sysctl.d/99-wireguard-manager.conf"
# Assigns a path for system backups
SYSTEM_BACKUP_PATH="/var/backups"
# Assigns a path for the WireGuard configuration backup file
WIREGUARD_CONFIG_BACKUP="${SYSTEM_BACKUP_PATH}/wireguard-manager.zip"
# Assigns a path for the WireGuard backup password file
WIREGUARD_BACKUP_PASSWORD_PATH="${HOME}/.wireguard-manager"
# Assigns a path for the DNS resolver configuration file
RESOLV_CONFIG="/etc/resolv.conf"
# Assigns a path for the old DNS resolver configuration file
RESOLV_CONFIG_OLD="${RESOLV_CONFIG}.old"
# Assigns a path for Unbound DNS resolver
UNBOUND_ROOT="/etc/unbound"
# Assigns a path for the WireGuard Manager script
UNBOUND_MANAGER="${UNBOUND_ROOT}/wireguard-manager"
# Assigns a path for the Unbound configuration file
UNBOUND_CONFIG="${UNBOUND_ROOT}/unbound.conf"
# Assigns a path for the Unbound root hints file
UNBOUND_ROOT_HINTS="${UNBOUND_ROOT}/root.hints"
# Assigns a path for the Unbound anchor file
UNBOUND_ANCHOR="/var/lib/unbound/root.key"
if { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
  UNBOUND_ANCHOR="${UNBOUND_ROOT}/root.key"
fi
# Assigns a path for the Unbound configuration directory
UNBOUND_CONFIG_DIRECTORY="${UNBOUND_ROOT}/unbound.conf.d"
# Assigns a path for the Unbound hosts configuration file
UNBOUND_CONFIG_HOST="${UNBOUND_CONFIG_DIRECTORY}/hosts.conf"
# Root hints sources, tried in order. The distro copy (dns-root-data) is used first if present.
UNBOUND_LOCAL_ROOT_HINTS="/usr/share/dns/root.hints"
UNBOUND_ROOT_HINTS_URLS=(
  "https://www.internic.net/domain/named.cache"
  "https://raw.githubusercontent.com/complexorganizations/wireguard-manager/main/assets/named.cache"
)
# Content-blocker sources, tried in order. Set CONTENT_BLOCKER_URL to use your own list first
# (plain domains or hosts format, e.g. https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts).
UNBOUND_CONFIG_HOST_URLS=(
  "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/assets/hosts"
  "https://cdn.jsdelivr.net/gh/complexorganizations/content-blocker/assets/hosts"
)
if [ -n "${CONTENT_BLOCKER_URL}" ]; then
  UNBOUND_CONFIG_HOST_URLS=("${CONTENT_BLOCKER_URL}" "${UNBOUND_CONFIG_HOST_URLS[@]}")
fi
WIREGUARD_MANAGER_UPDATE="https://raw.githubusercontent.com/Dario989/Wireguard/main/wireguard-manager.sh"
# Check if the CURRENT_DISTRO variable matches any of the following distros:
# fedora, centos, rhel, almalinux, or rocky
if { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
  # If the condition is true, set the SYSTEM_CRON_NAME variable to "crond"
  SYSTEM_CRON_NAME="crond"
# If the CURRENT_DISTRO variable matches any of the following distros:
# arch, archarm, or manjaro
elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
  # If the condition is true, set the SYSTEM_CRON_NAME variable to "cronie"
  SYSTEM_CRON_NAME="cronie"
else
  # If none of the above conditions are met, set the SYSTEM_CRON_NAME variable to "cron"
  SYSTEM_CRON_NAME="cron"
fi

# Detect the server's public addresses. The server's own interfaces are checked first; an outside
# lookup is only used when the server has no public address of its own (i.e. it is behind NAT).
function get-network-information() {
  local addr lookup
  # IPv4: every global address that isn't private, CGNAT or link-local.
  LOCAL_PUBLIC_IPV4_LIST=()
  for addr in $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut --delimiter="/" --fields=1); do
    if ! is-private-ipv4 "${addr}"; then
      LOCAL_PUBLIC_IPV4_LIST+=("${addr}")
    fi
  done
  DEFAULT_INTERFACE_IPV4=""
  if [ "${#LOCAL_PUBLIC_IPV4_LIST[@]}" -gt 0 ]; then
    SERVER_BEHIND_NAT=false
    DEFAULT_INTERFACE_IPV4="${LOCAL_PUBLIC_IPV4_LIST[0]}"
  else
    SERVER_BEHIND_NAT=true
    for lookup in 'https://checkip.amazonaws.com' 'https://icanhazip.com'; do
      addr=$(curl --ipv4 --connect-timeout 5 --max-time 10 --silent "${lookup}" | tr -d '[:space:]')
      if is-ipv4 "${addr}"; then
        DEFAULT_INTERFACE_IPV4="${addr}"
        break
      fi
    done
  fi
  # IPv6: global addresses, skipping ULA (fc00::/7), temporary privacy and deprecated addresses.
  LOCAL_PUBLIC_IPV6_LIST=()
  for addr in $(ip -6 -o addr show scope global 2>/dev/null | grep --invert-match 'temporary\|deprecated' | awk '{print $4}' | cut --delimiter="/" --fields=1); do
    if [[ ! "${addr}" =~ ^[fF][cCdD] ]]; then
      LOCAL_PUBLIC_IPV6_LIST+=("${addr}")
    fi
  done
  DEFAULT_INTERFACE_IPV6=""
  if [ "${#LOCAL_PUBLIC_IPV6_LIST[@]}" -gt 0 ]; then
    DEFAULT_INTERFACE_IPV6="${LOCAL_PUBLIC_IPV6_LIST[0]}"
  else
    for lookup in 'https://ifconfig.co' 'https://icanhazip.com'; do
      addr=$(curl --ipv6 --connect-timeout 5 --max-time 10 --silent "${lookup}" | tr -d '[:space:]')
      if is-ipv6 "${addr}"; then
        DEFAULT_INTERFACE_IPV6="${addr}"
        break
      fi
    done
  fi
}

# Usage Guide of the application
function usage-guide() {
  echo "Usage: ./$(basename "${0}") <command>"
  echo "  --install     Installs the WireGuard interface on your system"
  echo "  --start       Starts the WireGuard interface if it's not already running"
  echo "  --stop        Stops the WireGuard interface if it's currently running"
  echo "  --restart     Restarts the WireGuard interface"
  echo "  --list        Lists all the peers currently connected to the WireGuard interface"
  echo "  --add         Adds a new peer to the WireGuard interface"
  echo "  --remove      Removes a specified peer from the WireGuard interface"
  echo "  --reinstall   Reinstalls the WireGuard interface, keeping the current configuration"
  echo "  --uninstall   Uninstalls the WireGuard interface from your system"
  echo "  --update      Updates the WireGuard Manager to the latest version"
  echo "  --ddns        Updates the IP address of the WireGuard interface using Dynamic DNS"
  echo "  --backup      Creates a backup of your current WireGuard configuration"
  echo "  --restore     Restores the WireGuard configuration from a previous backup"
  echo "  --purge       Removes all peers from the WireGuard interface"
  echo "  --help        Displays this usage guide"
}

# Define a function that takes command line arguments as input
function usage() {
  # Check if there are any command line arguments left
  while [ $# -ne 0 ]; do
    # Use a switch-case statement to check the value of the first argument
    case ${1} in
    --install) # If it's "--install", set the variable HEADLESS_INSTALL to "true"
      shift
      HEADLESS_INSTALL=${HEADLESS_INSTALL=true}
      ;;
    --start) # If it's "--start", set the variable WIREGUARD_OPTIONS to 2
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=2}
      ;;
    --stop) # If it's "--stop", set the variable WIREGUARD_OPTIONS to 3
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=3}
      ;;
    --restart) # If it's "--restart", set the variable WIREGUARD_OPTIONS to 4
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=4}
      ;;
    --list) # If it's "--list", set the variable WIREGUARD_OPTIONS to 1
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=1}
      ;;
    --add) # If it's "--add", set the variable WIREGUARD_OPTIONS to 5
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=5}
      ;;
    --remove) # If it's "--remove", set the variable WIREGUARD_OPTIONS to 6
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=6}
      ;;
    --reinstall) # If it's "--reinstall", set the variable WIREGUARD_OPTIONS to 7
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=7}
      ;;
    --uninstall) # If it's "--uninstall", set the variable WIREGUARD_OPTIONS to 8
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=8}
      ;;
    --update) # If it's "--update", set the variable WIREGUARD_OPTIONS to 9
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=9}
      ;;
    --backup) # If it's "--backup", set the variable WIREGUARD_OPTIONS to 10
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=10}
      ;;
    --restore) # If it's "--restore", set the variable WIREGUARD_OPTIONS to 11
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=11}
      ;;
    --ddns) # If it's "--ddns", set the variable WIREGUARD_OPTIONS to 12
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=12}
      ;;
    --purge) # If it's "--purge", set the variable WIREGUARD_OPTIONS to 14
      shift
      WIREGUARD_OPTIONS=${WIREGUARD_OPTIONS=14}
      ;;
    --help) # If it's "--help", call the function usage-guide
      usage-guide
      exit 0
      ;;
    *) # If it's anything else, print an error message and call the function usage-guide, then exit
      echo "Invalid argument: ${1}"
      usage-guide
      exit
      ;;
    esac
  done
}

# Call the function usage with all the command line arguments
usage "$@"

# The function defines default values for configuration variables when installing WireGuard in headless mode.
# These variables include private subnet settings, server host settings, NAT choice, MTU choice, client allowed IP settings, automatic updates, automatic backup, DNS provider settings, content blocker settings, client name, and automatic config remover.
function headless-install() {
  # If headless installation is specified, set default values for configuration variables.
  if [ "${HEADLESS_INSTALL}" == true ]; then
    PRIVATE_SUBNET_V4_SETTINGS=${PRIVATE_SUBNET_V4_SETTINGS=1} # Default to 1 if not specified
    PRIVATE_SUBNET_V6_SETTINGS=${PRIVATE_SUBNET_V6_SETTINGS=1} # Default to 1 if not specified
    SERVER_HOST_V4_SETTINGS=${SERVER_HOST_V4_SETTINGS=1}       # Default to 1 if not specified
    SERVER_HOST_V6_SETTINGS=${SERVER_HOST_V6_SETTINGS=1}       # Default to 1 if not specified
    SERVER_PUB_NIC_SETTINGS=${SERVER_PUB_NIC_SETTINGS=1}       # Default to 1 if not specified
    SERVER_PORT_SETTINGS=${SERVER_PORT_SETTINGS=1}             # Default to 1 if not specified
    NAT_CHOICE_SETTINGS=${NAT_CHOICE_SETTINGS=1}               # Default to 1 if not specified
    MTU_CHOICE_SETTINGS=${MTU_CHOICE_SETTINGS=1}               # Default to 1 if not specified
    SERVER_HOST_SETTINGS=${SERVER_HOST_SETTINGS=1}             # Default to 1 if not specified
    CLIENT_ALLOWED_IP_SETTINGS=${CLIENT_ALLOWED_IP_SETTINGS=1} # Default to 1 if not specified
    AUTOMATIC_UPDATES_SETTINGS=${AUTOMATIC_UPDATES_SETTINGS=2} # Default to 2 (off) if not specified
    AUTOMATIC_BACKUP_SETTINGS=${AUTOMATIC_BACKUP_SETTINGS=1}   # Default to 1 if not specified
    DNS_PROVIDER_SETTINGS=${DNS_PROVIDER_SETTINGS=1}           # Default to 1 (Cloudflare) if not specified
    CONTENT_BLOCKER_SETTINGS=${CONTENT_BLOCKER_SETTINGS=1}     # Default to 1 if not specified
    CLIENT_NAME=${CLIENT_NAME=$(next-peer-name)}              # Default peer1, peer2, ... if not specified
    AUTOMATIC_CONFIG_REMOVER=${AUTOMATIC_CONFIG_REMOVER=1}     # Default to 1 if not specified
  fi
}

# Call the headless-install function to set default values for configuration variables in headless mode.
headless-install

# Set up the wireguard, if config it isn't already there.
if [ ! -f "${WIREGUARD_CONFIG}" ]; then

  # Define a function to set a custom IPv4 subnet
  function set-ipv4-subnet() {
    # Prompt the user for the desired IPv4 subnet
    echo "Please specify the IPv4 subnet you want to use for the WireGuard interface. This should be a private subnet that is not in use elsewhere on your network. For example, you might choose '10.0.0.0/24' if it's not already in use."
    echo "  1) 10.77.77.0/24 (Recommended)"
    echo "  2) Custom (Advanced)"
    # Keep prompting the user until they enter a valid subnet choice
    until [[ "${PRIVATE_SUBNET_V4_SETTINGS}" =~ ^[1-2]$ ]]; do
      read -rp "Subnet Choice [1-2]:" -e -i 1 PRIVATE_SUBNET_V4_SETTINGS
    done
    # Based on the user's choice, set the private IPv4 subnet
    case ${PRIVATE_SUBNET_V4_SETTINGS} in
    1)
      PRIVATE_SUBNET_V4="10.77.77.0/24" # Set a default IPv4 subnet
      ;;
    2)
      read -rp "Custom IPv4 Subnet:" PRIVATE_SUBNET_V4 # Prompt user for custom subnet
      if [ -z "${PRIVATE_SUBNET_V4}" ]; then           # If the user did not enter a subnet, set default
        PRIVATE_SUBNET_V4="10.77.77.0/24"
      fi
      ;;
    esac
  }

  # Call the function to set the custom IPv4 subnet
  set-ipv4-subnet

  # Define a function to set a custom IPv6 subnet
  function set-ipv6-subnet() {
    # Ask the user which IPv6 subnet they want to use
    echo "Please specify the IPv6 subnet you want to use for the WireGuard interface. This should be a private subnet that is not in use elsewhere on your network. For example, you might choose 'fd77:77:77::0/64' if it's not already in use."
    echo "  1) fd77:77:77::0/64 (Recommended)"
    echo "  2) Custom (Advanced)"
    # Use a loop to ensure the user inputs a valid option
    until [[ "${PRIVATE_SUBNET_V6_SETTINGS}" =~ ^[1-2]$ ]]; do
      read -rp "Please choose the IPv6 subnet for your WireGuard interface [Option 1-2]: " -e -i 1 PRIVATE_SUBNET_V6_SETTINGS
    done
    # Use a case statement to set the IPv6 subnet based on the user's choice
    case ${PRIVATE_SUBNET_V6_SETTINGS} in
    1)
      # Use the recommended IPv6 subnet if the user chooses option 1
      PRIVATE_SUBNET_V6="fd77:77:77::0/64"
      ;;
    2)
      # Ask the user for a custom IPv6 subnet if they choose option 2
      read -rp "Please enter a custom IPv6 subnet for your WireGuard interface: " PRIVATE_SUBNET_V6
      # If the user does not input a subnet, use the recommended one
      if [ -z "${PRIVATE_SUBNET_V6}" ]; then
        PRIVATE_SUBNET_V6="fd77:77:77::0/64"
      fi
      ;;
    esac
  }

  # Call the set-ipv6-subnet function to set the custom IPv6 subnet
  set-ipv6-subnet

  # Define the private subnet mask for the IPv4 network used by the WireGuard interface
  PRIVATE_SUBNET_MASK_V4=$(echo "${PRIVATE_SUBNET_V4}" | cut --delimiter="/" --fields=2) # Get the subnet mask of IPv4
  # Define the IPv4 gateway for the WireGuard interface
  GATEWAY_ADDRESS_V4=$(echo "${PRIVATE_SUBNET_V4}" | cut --delimiter="." --fields=1-3).1 # Get the gateway address of IPv4
  # Define the private subnet mask for the IPv6 network used by the WireGuard interface
  PRIVATE_SUBNET_MASK_V6=$(echo "${PRIVATE_SUBNET_V6}" | cut --delimiter="/" --fields=2) # Get the subnet mask of IPv6
  # Define the IPv6 gateway for the WireGuard interface
  GATEWAY_ADDRESS_V6=$(echo "${PRIVATE_SUBNET_V6}" | cut --delimiter=":" --fields=1-3)::1 # Get the gateway address of IPv6
  # Retrieve the networking configuration details
  get-network-information
  # Call a function to get the networking data

  # Define a function to retrieve the IPv4 address of the WireGuard interface
  function test-connectivity-v4() {
    local i
    echo "Which public IPv4 address should clients connect to?"
    echo "  1) Auto-detect (Recommended)${DEFAULT_INTERFACE_IPV4:+ [${DEFAULT_INTERFACE_IPV4}]}"
    echo "  2) Custom address or hostname (Advanced)"
    until [[ "${SERVER_HOST_V4_SETTINGS}" =~ ^[1-2]$ ]]; do
      read -rp "IPv4 Choice [1-2]:" -e -i 1 SERVER_HOST_V4_SETTINGS
    done
    case ${SERVER_HOST_V4_SETTINGS} in
    1)
      if [ "${#LOCAL_PUBLIC_IPV4_LIST[@]}" -gt 1 ] && [ "${HEADLESS_INSTALL}" != true ]; then
        # Several public addresses on this server: let the user pick one.
        echo "This server has several public IPv4 addresses:"
        for i in "${!LOCAL_PUBLIC_IPV4_LIST[@]}"; do
          echo "  $((i + 1))) ${LOCAL_PUBLIC_IPV4_LIST[i]}"
        done
        until [[ "${IPV4_ADDRESS_CHOICE}" =~ ^[0-9]+$ ]] && [ "${IPV4_ADDRESS_CHOICE}" -ge 1 ] && [ "${IPV4_ADDRESS_CHOICE}" -le "${#LOCAL_PUBLIC_IPV4_LIST[@]}" ]; do
          read -rp "IPv4 address [1-${#LOCAL_PUBLIC_IPV4_LIST[@]}]:" -e -i 1 IPV4_ADDRESS_CHOICE
        done
        SERVER_HOST_V4="${LOCAL_PUBLIC_IPV4_LIST[IPV4_ADDRESS_CHOICE - 1]}"
      elif [ "${SERVER_BEHIND_NAT}" == true ] && [ "${HEADLESS_INSTALL}" != true ]; then
        # Only private addresses here: confirm the public one found online, or enter a hostname.
        echo "This server is behind NAT. What is its public IPv4 address or hostname?"
        until [ -n "${SERVER_HOST_V4}" ]; do
          read -rp "Public IPv4 address / hostname:" -e -i "${DEFAULT_INTERFACE_IPV4}" SERVER_HOST_V4
        done
      else
        SERVER_HOST_V4="${DEFAULT_INTERFACE_IPV4}"
      fi
      ;;
    2)
      until [ -n "${SERVER_HOST_V4}" ]; do
        read -rp "Custom IPv4 address / hostname:" -e -i "${DEFAULT_INTERFACE_IPV4}" SERVER_HOST_V4
      done
      ;;
    esac
  }

  # Call the function to retrieve the IPv4 address
  test-connectivity-v4
  # Invoke the function to get the IPv4 address

  # Define a function to retrieve the IPv6 address of the WireGuard interface
  function test-connectivity-v6() {
    local i
    echo "Which public IPv6 address should clients connect to?"
    echo "  1) Auto-detect (Recommended)${DEFAULT_INTERFACE_IPV6:+ [${DEFAULT_INTERFACE_IPV6}]}"
    echo "  2) Custom address or hostname (Advanced)"
    until [[ "${SERVER_HOST_V6_SETTINGS}" =~ ^[1-2]$ ]]; do
      read -rp "IPv6 Choice [1-2]:" -e -i 1 SERVER_HOST_V6_SETTINGS
    done
    case ${SERVER_HOST_V6_SETTINGS} in
    1)
      if [ "${#LOCAL_PUBLIC_IPV6_LIST[@]}" -gt 1 ] && [ "${HEADLESS_INSTALL}" != true ]; then
        echo "This server has several public IPv6 addresses:"
        for i in "${!LOCAL_PUBLIC_IPV6_LIST[@]}"; do
          echo "  $((i + 1))) ${LOCAL_PUBLIC_IPV6_LIST[i]}"
        done
        until [[ "${IPV6_ADDRESS_CHOICE}" =~ ^[0-9]+$ ]] && [ "${IPV6_ADDRESS_CHOICE}" -ge 1 ] && [ "${IPV6_ADDRESS_CHOICE}" -le "${#LOCAL_PUBLIC_IPV6_LIST[@]}" ]; do
          read -rp "IPv6 address [1-${#LOCAL_PUBLIC_IPV6_LIST[@]}]:" -e -i 1 IPV6_ADDRESS_CHOICE
        done
        SERVER_HOST_V6="${LOCAL_PUBLIC_IPV6_LIST[IPV6_ADDRESS_CHOICE - 1]}"
      else
        SERVER_HOST_V6="${DEFAULT_INTERFACE_IPV6}"
      fi
      ;;
    2)
      until [ -n "${SERVER_HOST_V6}" ]; do
        read -rp "Custom IPv6 address / hostname:" -e -i "${DEFAULT_INTERFACE_IPV6}" SERVER_HOST_V6
      done
      ;;
    esac
  }

  # Call the function to retrieve the IPv6 address
  test-connectivity-v6

  # Define a function to identify the public Network Interface Card (NIC).
  function server-pub-nic() {
    # Prompt the user to select the method for identifying the NIC.
    echo "How would you like to identify the Network Interface Card (NIC)?"
    echo "  1) IP Route (Recommended)"
    echo "  2) Custom Input (Advanced)"
    # Loop until the user provides a valid input (either 1 or 2).
    until [[ "${SERVER_PUB_NIC_SETTINGS}" =~ ^[1-2]$ ]]; do
      read -rp "NIC Choice [1-2]:" -e -i 1 SERVER_PUB_NIC_SETTINGS
    done
    # Execute a case statement based on the user's choice.
    case ${SERVER_PUB_NIC_SETTINGS} in
    1)
      # Use the IP route command to automatically identify the NIC.
      SERVER_PUB_NIC="$(ip route | grep default | head --lines=1 | cut --delimiter=" " --fields=5)"
      # If no NIC is found, exit the script with an error message.
      if [ -z "${SERVER_PUB_NIC}" ]; then
        echo "Error: Unable to identify your server's public network interface."
        exit
      fi
      ;;
    2)
      # Prompt the user to manually input the NIC.
      read -rp "Custom NIC:" SERVER_PUB_NIC
      # If the user doesn't provide an input, use the IP route command to identify the NIC.
      if [ -z "${SERVER_PUB_NIC}" ]; then
        SERVER_PUB_NIC="$(ip route | grep default | head --lines=1 | cut --delimiter=" " --fields=5)"
      fi
      ;;
    esac
  }

  # Call the function to identify the public NIC.
  server-pub-nic

  # Define a function to configure the WireGuard server's listening port
  function set-port() {
    # Prompt the user to specify the port for the WireGuard server
    echo "What port do you want WireGuard server to listen to?"
    # Provide the user with options for setting the port
    echo "  1) 51820 (Recommended)"
    echo "  2) Custom (Advanced)"
    # Continue prompting the user until a valid option (1 or 2) is selected
    until [[ "${SERVER_PORT_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Ask the user for their port choice, with 1 as the default option
      read -rp "Port Choice [1-2]:" -e -i 1 SERVER_PORT_SETTINGS
    done
    # Set the SERVER_PORT variable based on the user's choice
    case ${SERVER_PORT_SETTINGS} in
    1)
      SERVER_PORT="51820"
      # If the chosen port is already in use, display an error message and exit the script
      if [ "$(lsof -i UDP:"${SERVER_PORT}")" ]; then
        echo "Error: Please use a different port because ${SERVER_PORT} is already in use."
        exit
      fi
      ;;
    2)
      # Continue prompting the user until a valid custom port number (between 1 and 65535) is entered
      until [[ "${SERVER_PORT}" =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Custom port [1-65535]:" SERVER_PORT
      done
      # If no custom port is entered, set the SERVER_PORT variable to the default of 51820
      if [ -z "${SERVER_PORT}" ]; then
        SERVER_PORT="51820"
      fi
      # If the chosen port is already in use, display an error message and exit the script
      if [ "$(lsof -i UDP:"${SERVER_PORT}")" ]; then
        echo "Error: The port ${SERVER_PORT} is already used by a different application, please use a different port."
        exit
      fi
      ;;
    esac
  }

  # Invoke the set-port function to configure the WireGuard server's listening port
  set-port

  # Define a function to set the NAT keepalive interval.
  function nat-keepalive() {
    # Prompt the user to specify the NAT keepalive interval.
    echo "What do you want your NAT keepalive interval to be?"
    # Provide the user with options for setting the interval.
    echo "  1) 25 seconds (Default)"
    echo "  2) Custom (Advanced)"
    # Continue prompting the user until a valid option (1 or 2) is selected.
    until [[ "${NAT_CHOICE_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Ask the user for their interval choice, with 1 as the default option.
      read -rp "Keepalive Choice [1-2]:" -e -i 1 NAT_CHOICE_SETTINGS
    done
    # Set the NAT_CHOICE variable based on the user's choice.
    case ${NAT_CHOICE_SETTINGS} in
    1)
      # If the user chose the default option, set the NAT_CHOICE to 25 seconds.
      NAT_CHOICE="25"
      ;;
    2)
      # If the user chose the custom option, prompt them to enter a custom interval.
      until [[ "${NAT_CHOICE}" =~ ^[0-9]+$ ]] && [ "${NAT_CHOICE}" -ge 1 ] && [ "${NAT_CHOICE}" -le 65535 ]; do
        read -rp "Custom NAT [1-65535]:" NAT_CHOICE
      done
      # If no custom interval is entered, set the NAT_CHOICE variable to the default of 25 seconds.
      if [ -z "${NAT_CHOICE}" ]; then
        NAT_CHOICE="25"
      fi
      ;;
    esac
  }
  # Invoke the nat-keepalive function to set the NAT keepalive interval.
  nat-keepalive

  # Define a function to configure the Maximum Transmission Unit (MTU) settings.
  function mtu-set() {
    # Ask the user to specify the MTU settings.
    echo "What MTU do you want to use?"
    # Provide the user with options for setting the MTU.
    echo "  1) 1420 for Interface, automatic for Peers (Recommended)"
    echo "  2) Custom (Advanced)"
    # Continue prompting the user until a valid option (1 or 2) is selected.
    until [[ "${MTU_CHOICE_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Ask the user for their MTU choice, with 1 as the default option.
      read -rp "MTU Choice [1-2]:" -e -i 1 MTU_CHOICE_SETTINGS
    done
    # Set the MTU variables based on the user's choice.
    case ${MTU_CHOICE_SETTINGS} in
    1)
      # If the user chose the default option, set the Interface MTU to 1420 and Peer MTU to 1280.
      INTERFACE_MTU_CHOICE="1420"
      # "auto" leaves MTU out of client configs so each device uses WireGuard's default.
      PEER_MTU_CHOICE="auto"
      ;;
    2)
      # If the user chose the custom option, prompt them to enter a custom MTU for Interface and Peer.
      until [[ "${INTERFACE_MTU_CHOICE}" =~ ^[0-9]+$ ]] && [ "${INTERFACE_MTU_CHOICE}" -ge 1 ] && [ "${INTERFACE_MTU_CHOICE}" -le 65535 ]; do
        read -rp "Custom Interface MTU [1-65535]:" INTERFACE_MTU_CHOICE
      done
      # If no custom Interface MTU is entered, set the INTERFACE_MTU_CHOICE variable to the default of 1420.
      if [ -z "${INTERFACE_MTU_CHOICE}" ]; then
        INTERFACE_MTU_CHOICE="1420"
      fi
      until [[ "${PEER_MTU_CHOICE}" =~ ^[0-9]+$ ]] && [ "${PEER_MTU_CHOICE}" -ge 1 ] && [ "${PEER_MTU_CHOICE}" -le 65535 ]; do
        read -rp "Custom Peer MTU [1-65535]:" PEER_MTU_CHOICE
      done
      # If no custom Peer MTU is entered, set the PEER_MTU_CHOICE variable to the default of 1280.
      if [ -z "${PEER_MTU_CHOICE}" ]; then
        PEER_MTU_CHOICE="1280"
      fi
      ;;
    esac
  }

  # Invoke the mtu-set function to configure the MTU settings.
  mtu-set

  # Define a function to select the IP version for the WireGuard server.
  function ipvx-select() {
    # Ask the user to specify the IP version to use for connecting to the WireGuard server.
    echo "Which IP version do you want to use for the WireGuard server?"
    # Provide the user with options for setting the IP version.
    echo "  1) IPv4 (Recommended)"
    echo "  2) IPv6"
    # Continue prompting the user until a valid option (1 or 2) is selected.
    until [[ "${SERVER_HOST_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Ask the user for their IP version choice, with 1 as the default option.
      read -rp "IP Version Choice [1-2]:" -e -i 1 SERVER_HOST_SETTINGS
    done
    # Set the SERVER_HOST variable based on the user's choice.
    case ${SERVER_HOST_SETTINGS} in
    1)
      if [ -n "${SERVER_HOST_V4}" ]; then
        SERVER_HOST="${SERVER_HOST_V4}"
      else
        SERVER_HOST="${SERVER_HOST_V6}"
      fi
      ;;
    2)
      if [ -n "${SERVER_HOST_V6}" ]; then
        SERVER_HOST="${SERVER_HOST_V6}"
      else
        SERVER_HOST="${SERVER_HOST_V4}"
      fi
      ;;
    esac
    if [ -z "${SERVER_HOST}" ]; then
      echo "Error: Could not determine a public address for this server. Choose the custom option and enter it manually."
      exit 1
    fi
    # A literal IPv6 address needs brackets in an endpoint; hostnames and IPv4 don't.
    if is-ipv6 "${SERVER_HOST}"; then
      SERVER_HOST="[${SERVER_HOST}]"
    fi
  }

  # Invoke the ipvx-select function to select the IP version for the WireGuard server.
  ipvx-select

  # Define a function to configure the type of traffic the client is allowed to forward through WireGuard.
  function client-allowed-ip() {
    # Ask the user to specify the type of traffic to be forwarded.
    echo "What type of traffic do you want the client to forward through WireGuard?"
    # Provide the user with options for setting the traffic type.
    echo "  1) All Traffic (Recommended)"
    echo "  2) Custom Traffic (Advanced)"
    # Continue prompting the user until a valid option (1 or 2) is selected.
    until [[ "${CLIENT_ALLOWED_IP_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Ask the user for their traffic type choice, with 1 as the default option.
      read -rp "Traffic Type Choice [1-2]:" -e -i 1 CLIENT_ALLOWED_IP_SETTINGS
    done
    # Set the CLIENT_ALLOWED_IP variable based on the user's choice.
    case ${CLIENT_ALLOWED_IP_SETTINGS} in
    1)
      # If the user chose the default option, set the CLIENT_ALLOWED_IP to allow all traffic.
      CLIENT_ALLOWED_IP="0.0.0.0/0,::/0"
      ;;
    2)
      # If the user chose the custom option, prompt them to enter a custom IP range.
      read -rp "Custom IP Range:" CLIENT_ALLOWED_IP
      # If no custom IP range is entered, set the CLIENT_ALLOWED_IP variable to allow all traffic.
      if [ -z "${CLIENT_ALLOWED_IP}" ]; then
        CLIENT_ALLOWED_IP="0.0.0.0/0,::/0"
      fi
      ;;
    esac
  }

  # Invoke the client-allowed-ip function to configure the type of traffic the client is allowed to forward.
  client-allowed-ip

  # Function to configure automatic updates
  function enable-automatic-updates() {
    # Prompt the user to decide if they want to enable automatic updates
    echo "Would you like to setup real-time updates?"
    # Option 1: Enable automatic updates
    echo "  1) Yes"
    # Option 2: Disable automatic updates
    echo "  2) No (Recommended)"
    # Loop until a valid choice (1 or 2) is made
    until [[ "${AUTOMATIC_UPDATES_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Read user input for automatic updates setting
      read -rp "Automatic Updates [1-2]:" -e -i 2 AUTOMATIC_UPDATES_SETTINGS
    done
    # Evaluate user choice for automatic updates
    case ${AUTOMATIC_UPDATES_SETTINGS} in
    1)
      # If user chose to enable automatic updates, set up a cron job
      crontab -l 2>/dev/null | {
        cat
        # Add a cron job to run the script with --update option every day at midnight
        echo "0 0 * * * ${CURRENT_FILE_PATH} --update"
      } | sort --unique | crontab -
      # Check the init system in use
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        # If systemd is in use, enable and start the cron service
        systemctl enable --now ${SYSTEM_CRON_NAME}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        # If initd is in use, start the cron service
        service ${SYSTEM_CRON_NAME} start
      fi
      ;;
    2)
      # If user chose to disable automatic updates, display a confirmation message
      echo "Real-time Updates Disabled"
      ;;
    esac
  }

  # Invoke the function to configure automatic updates
  enable-automatic-updates

  # Function to configure automatic backup
  function enable-automatic-backup() {
    # Prompt the user to decide if they want to enable automatic backup
    echo "Would you like to setup real-time backup?"
    # Option 1: Enable automatic backup
    echo "  1) Yes (Recommended)"
    # Option 2: Disable automatic backup
    echo "  2) No (Advanced)"
    # Loop until a valid choice (1 or 2) is made
    until [[ "${AUTOMATIC_BACKUP_SETTINGS}" =~ ^[1-2]$ ]]; do
      # Read user input for automatic backup setting
      read -rp "Automatic Backup [1-2]:" -e -i 1 AUTOMATIC_BACKUP_SETTINGS
    done
    # Evaluate user choice for automatic backup
    case ${AUTOMATIC_BACKUP_SETTINGS} in
    1)
      # If user chose to enable automatic backup, set up a cron job
      crontab -l 2>/dev/null | {
        cat
        # Add a cron job to run the script with --backup option every day at midnight
        echo "0 0 * * * ${CURRENT_FILE_PATH} --backup"
      } | sort --unique | crontab -
      # Check the init system in use
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        # If systemd is in use, enable and start the cron service
        systemctl enable --now ${SYSTEM_CRON_NAME}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        # If initd is in use, start the cron service
        service ${SYSTEM_CRON_NAME} start
      fi
      ;;
    2)
      # If user chose to disable automatic backup, display a confirmation message
      echo "Real-time Backup Disabled"
      ;;
    esac
  }

  # Invoke the function to configure automatic backup
  enable-automatic-backup

  # Function to choose the DNS server the WireGuard clients will use.
  # Public resolvers come first; Unbound (a local recursive resolver that also takes over
  # the server's own /etc/resolv.conf and port 53) is the last, advanced option.
  function ask-install-dns() {
    echo "Which DNS server should the WireGuard clients use?"
    echo "  1) Cloudflare (Recommended)"
    echo "  2) AdGuard (blocks ads)"
    echo "  3) NextDNS"
    echo "  4) OpenDNS"
    echo "  5) Google"
    echo "  6) Verisign"
    echo "  7) Quad9 (blocks malware)"
    echo "  8) FDN"
    echo "  9) Custom (Advanced)"
    echo "  10) Unbound on this server (Advanced: replaces the server's own DNS, optional content-blocker)"
    DNS_PROVIDER_MAX=10
    # If Pi-Hole is installed, add it as an option.
    if [ -x "$(command -v pihole)" ]; then
      echo "  11) Pi-Hole on this server (Advanced)"
      DNS_PROVIDER_MAX=11
    fi
    until [[ "${DNS_PROVIDER_SETTINGS}" =~ ^[0-9]+$ ]] && [ "${DNS_PROVIDER_SETTINGS}" -ge 1 ] && [ "${DNS_PROVIDER_SETTINGS}" -le "${DNS_PROVIDER_MAX}" ]; do
      read -rp "DNS [1-${DNS_PROVIDER_MAX}]:" -e -i 1 DNS_PROVIDER_SETTINGS
    done
    case ${DNS_PROVIDER_SETTINGS} in
    1)
      CLIENT_DNS="1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
      ;;
    2)
      CLIENT_DNS="94.140.14.14,94.140.15.15,2a10:50c0::ad1:ff,2a10:50c0::ad2:ff"
      ;;
    3)
      CLIENT_DNS="45.90.28.167,45.90.30.167,2a07:a8c0::12:cf53,2a07:a8c1::12:cf53"
      ;;
    4)
      CLIENT_DNS="208.67.222.222,208.67.220.220,2620:119:35::35,2620:119:53::53"
      ;;
    5)
      CLIENT_DNS="8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844"
      ;;
    6)
      CLIENT_DNS="64.6.64.6,64.6.65.6,2620:74:1b::1:1,2620:74:1c::2:2"
      ;;
    7)
      CLIENT_DNS="9.9.9.9,149.112.112.112,2620:fe::fe,2620:fe::9"
      ;;
    8)
      CLIENT_DNS="80.67.169.40,80.67.169.12,2001:910:800::40,2001:910:800::12"
      ;;
    9)
      # Accept only real IPv4/IPv6 addresses; empty input falls back to Cloudflare.
      until [ -n "${CLIENT_DNS}" ]; do
        read -rp "Custom DNS servers (IPv4/IPv6, comma or space separated):" CUSTOM_DNS_INPUT
        if [ -z "${CUSTOM_DNS_INPUT}" ]; then
          CLIENT_DNS="1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
          break
        fi
        CUSTOM_DNS_VALID=true
        for CUSTOM_DNS_IP in ${CUSTOM_DNS_INPUT//,/ }; do
          if is-ipv4 "${CUSTOM_DNS_IP}" || is-ipv6 "${CUSTOM_DNS_IP}"; then
            CLIENT_DNS="${CLIENT_DNS:+${CLIENT_DNS},}${CUSTOM_DNS_IP}"
          else
            echo "Invalid DNS server address: ${CUSTOM_DNS_IP}"
            CUSTOM_DNS_VALID=false
          fi
        done
        if [ "${CUSTOM_DNS_VALID}" != true ]; then
          CLIENT_DNS=""
        fi
      done
      ;;
    10)
      # Unbound sets CLIENT_DNS to the tunnel gateway itself during install-unbound.
      INSTALL_UNBOUND=true
      echo "Do you want to prevent advertisements, tracking, malware, and phishing using the content-blocker?"
      echo "  1) Yes (Recommended)"
      echo "  2) No"
      until [[ "${CONTENT_BLOCKER_SETTINGS}" =~ ^[1-2]$ ]]; do
        read -rp "Content Blocker Choice [1-2]:" -e -i 1 CONTENT_BLOCKER_SETTINGS
      done
      case ${CONTENT_BLOCKER_SETTINGS} in
      1)
        INSTALL_BLOCK_LIST=true
        ;;
      2)
        INSTALL_BLOCK_LIST=false
        ;;
      esac
      ;;
    11)
      CLIENT_DNS="${GATEWAY_ADDRESS_V4},${GATEWAY_ADDRESS_V6}"
      ;;
    esac
  }

  # Invoke the ask-install-dns function to begin the DNS provider selection process.
  ask-install-dns

  # Function to prompt for the name of the first WireGuard peer.
  function client-name() {
    # If CLIENT_NAME variable is not set, prompt the user for input.
    if [ -z "${CLIENT_NAME}" ]; then
      # Display naming rules to the user.
      echo "Please provide a name for the WireGuard Peer. The name should be a single word, without special characters or spaces."
      # Read the user's input, offering a random string as the default name.
      read -rp "Client name:" -e -i "$(next-peer-name)" CLIENT_NAME
    fi
    # If no name is provided by the user, assign a random string as the name.
    if [ -z "${CLIENT_NAME}" ]; then
      CLIENT_NAME="$(next-peer-name)"
    fi
    validate-peer-name "${CLIENT_NAME}"
  }

  # Invoke the function to prompt for the first WireGuard peer's name.
  client-name

  # Function to set up automatic deletion of WireGuard peers.
  function auto-remove-config() {
    # Ask the user if they want to set an expiration date for the peer.
    echo "Do you want to set an expiration date for the peer?"
    echo "  1) Yes, expire after one year (Recommended)"
    echo "  2) No, do not expire"
    # Keep asking until the user enters 1 or 2.
    until [[ "${AUTOMATIC_CONFIG_REMOVER}" =~ ^[1-2]$ ]]; do
      read -rp "Choose an option for peer expiration [1-2]:" -e -i 1 AUTOMATIC_CONFIG_REMOVER
    done
    # Execute actions based on the user's choice.
    case ${AUTOMATIC_CONFIG_REMOVER} in
    1)
      # If the user chose to expire the peer, set the expiration flag to true.
      AUTOMATIC_WIREGUARD_EXPIRATION=true
      # Depending on the init system, enable and start the cron service.
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl enable --now ${SYSTEM_CRON_NAME}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service ${SYSTEM_CRON_NAME} start
      fi
      ;;
    2)
      # If the user chose not to expire the peer, set the expiration flag to false.
      AUTOMATIC_WIREGUARD_EXPIRATION=false
      ;;
    esac
  }

  # Invoke the function to set up automatic deletion of WireGuard peers.
  auto-remove-config

  # Function to verify kernel version and install necessary kernel headers.
  function install-kernel-headers() {
    # Define the minimum kernel version required and extract its major and minor version numbers.
    MINIMUM_KERNEL_VERSION="5.6"
    MINIMUM_KERNEL_MAJOR_VERSION=$(echo ${MINIMUM_KERNEL_VERSION} | cut --delimiter="." --fields=1)
    MINIMUM_KERNEL_MINOR_VERSION=$(echo ${MINIMUM_KERNEL_VERSION} | cut --delimiter="." --fields=2)
    # Check if the current kernel version is less than or equal to the minimum required version.
    if [ "${CURRENT_KERNEL_MAJOR_VERSION}" -le "${MINIMUM_KERNEL_MAJOR_VERSION}" ]; then
      INSTALL_LINUX_HEADERS=true
    fi
    # If the current kernel major version matches the minimum required major version, compare minor versions.
    if [ "${CURRENT_KERNEL_MAJOR_VERSION}" == "${MINIMUM_KERNEL_MAJOR_VERSION}" ]; then
      # If the current minor version is less than the required, set flag to install headers.
      if [ "${CURRENT_KERNEL_MINOR_VERSION}" -lt "${MINIMUM_KERNEL_MINOR_VERSION}" ]; then
        INSTALL_LINUX_HEADERS=true
      fi
      # If the current minor version is greater than or equal to the required, set flag to not install headers.
      if [ "${CURRENT_KERNEL_MINOR_VERSION}" -ge "${MINIMUM_KERNEL_MINOR_VERSION}" ]; then
        INSTALL_LINUX_HEADERS=false
      fi
    fi
    # If the flag to install headers is set, install appropriate headers based on the Linux distribution.
    if [ "${INSTALL_LINUX_HEADERS}" == true ]; then
      if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        apt-get update
        apt-get install linux-headers-"$(uname --kernel-release)" -y
      elif [ "${CURRENT_DISTRO}" == "raspbian" ]; then
        apt-get update
        apt-get install raspberrypi-kernel-headers -y
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Su --noconfirm --needed linux-headers
      elif { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "ol" ]; }; then
        yum check-update
        yum install kernel-headers-"$(uname --kernel-release)" kernel-devel-"$(uname --kernel-release)" -y
      elif { [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        yum check-update
        yum install kernel-headers-"$(uname --kernel-release)" kernel-devel-"$(uname --kernel-release)" -y
      fi
    fi
  }

  # Invoke the function to verify kernel version and install necessary kernel headers.
  install-kernel-headers

  # Function to install either resolvconf or openresolv, depending on the distribution.
  function install-resolvconf-or-openresolv() {
    # Check if resolvconf is already installed on the system.
    if [ ! -x "$(command -v resolvconf)" ]; then
      # If resolvconf is not installed, install it for Ubuntu, Debian, Raspbian, Pop, Kali, Linux Mint, and Neon distributions.
      if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        apt-get install resolvconf -y
      # For CentOS, RHEL, AlmaLinux, and Rocky distributions, install openresolv.
      elif { [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        # If the distribution is CentOS 7, enable the copr repository before installing openresolv.
        if [ "${CURRENT_DISTRO}" == "centos" ] && [ "${CURRENT_DISTRO_MAJOR_VERSION}" == 7 ]; then
          yum copr enable macieks/openresolv -y
        fi
        yum install openresolv -y
      # For Fedora and Oracle Linux distributions, install openresolv.
      elif { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "ol" ]; }; then
        yum install openresolv -y
      # For Arch, Arch ARM, and Manjaro distributions, install resolvconf.
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Su --noconfirm --needed resolvconf
      # For Alpine Linux, install resolvconf.
      elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
        apk add resolvconf
      # For FreeBSD, install resolvconf.
      elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
        pkg install resolvconf
      fi
    fi
  }

  # Invoke the function to install either resolvconf or openresolv, depending on the distribution.
  install-resolvconf-or-openresolv

  # Function to install the WireGuard server if it's not already installed.
  function install-wireguard-server() {
    # Verify if the WireGuard command (wg) is available on the system.
    if [ ! -x "$(command -v wg)" ]; then
      # For Debian-based distributions, update the package list and install WireGuard.
      if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        apt-get update
        apt-get install wireguard -y
      # For Arch-based distributions, update the package list and install WireGuard tools.
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Su --noconfirm --needed wireguard-tools
      elif [ "${CURRENT_DISTRO}" = "fedora" ]; then
        dnf check-update
        dnf copr enable jdoss/wireguard -y
        dnf install wireguard-tools -y
      # For CentOS, update the package list and install WireGuard tools and kernel module.
      elif [ "${CURRENT_DISTRO}" == "centos" ]; then
        yum check-update
        yum install kmod-wireguard wireguard-tools -y
      # For RHEL, install necessary repositories and then install WireGuard tools and kernel module.
      elif [ "${CURRENT_DISTRO}" == "rhel" ]; then
        yum check-update
        yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-"${CURRENT_DISTRO_MAJOR_VERSION}".noarch.rpm https://www.elrepo.org/elrepo-release-"${CURRENT_DISTRO_MAJOR_VERSION}".el"${CURRENT_DISTRO_MAJOR_VERSION}".elrepo.noarch.rpm
        yum check-update
        yum install kmod-wireguard wireguard-tools -y
      # For Alpine Linux, update the package list and install WireGuard tools.
      elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
        apk update
        apk add wireguard-tools
      # For FreeBSD, update the package list and install WireGuard.
      elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
        pkg update
        pkg install wireguard
      # For AlmaLinux and Rocky, update the package list and install WireGuard tools and kernel module.
      elif { [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        yum check-update
        yum install kmod-wireguard wireguard-tools -y
      # For Oracle Linux, configure necessary repositories and then install WireGuard tools.
      elif [ "${CURRENT_DISTRO}" == "ol" ]; then
        yum check-update
        yum install oraclelinux-developer-release-el"${CURRENT_DISTRO_MAJOR_VERSION}" -y
        yum config-manager --disable ol"${CURRENT_DISTRO_MAJOR_VERSION}"_developer
        yum config-manager --enable ol"${CURRENT_DISTRO_MAJOR_VERSION}"_developer_UEKR6
        yum config-manager --save --setopt=ol"${CURRENT_DISTRO_MAJOR_VERSION}"_developer_UEKR6.includepkgs='wireguard-tools*'
        yum install wireguard-tools -y
      fi
    fi
  }

  # Invoke the function to install the WireGuard server.
  install-wireguard-server

  # Function to install Unbound, a DNS resolver, if required and not already installed.
  function install-unbound() {
    # If INSTALL_UNBOUND is true and Unbound is not installed, proceed with installation.
    if [ "${INSTALL_UNBOUND}" == true ]; then
      if [ ! -x "$(command -v unbound)" ]; then
        # Installation commands for Unbound vary based on the Linux distribution.
        # The following checks the distribution and installs Unbound accordingly.
        # For Debian-based distributions:
        if { [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
          apt-get install unbound unbound-host unbound-anchor -y
          # If the distribution is Ubuntu, disable systemd-resolved.
          if [ "${CURRENT_DISTRO}" == "ubuntu" ]; then
            if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
              systemctl disable --now systemd-resolved
            elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
              service systemd-resolved stop
            fi
          fi
        # For CentOS, RHEL, AlmaLinux, and Rocky:
        elif { [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
          yum install unbound unbound-host unbound-anchor -y
        # For Fedora:
        elif [ "${CURRENT_DISTRO}" == "fedora" ]; then
          dnf install unbound unbound-host unbound-anchor -y
        # For Arch-based distributions:
        elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
          pacman -Su --noconfirm --needed unbound
        # For Alpine Linux:
        elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
          apk add unbound unbound-host unbound-anchor
        # For FreeBSD:
        elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
          pkg install unbound unbound-host unbound-anchor
        # For Oracle Linux:
        elif [ "${CURRENT_DISTRO}" == "ol" ]; then
          yum install unbound unbound-host unbound-anchor -y
        fi
      fi
      # Configure Unbound using anchor and root hints.
      unbound-anchor -a ${UNBOUND_ANCHOR}
      # Fetch root hints (distro copy first, then download).
      update-root-hints
      # Configure Unbound settings.
      # The settings are stored in a temporary variable and then written to the Unbound configuration file.
      # If INSTALL_BLOCK_LIST is true, include a block list in the Unbound configuration.
      # Configure Unbound settings.
      UNBOUND_TEMP_INTERFACE_INFO="server:
\tnum-threads: $(nproc)
\tverbosity: 0
\troot-hints: ${UNBOUND_ROOT_HINTS}
\tauto-trust-anchor-file: ${UNBOUND_ANCHOR}
\tinterface: 0.0.0.0
\tinterface: ::0
\tport: 53
\tmax-udp-size: 3072
\taccess-control: 0.0.0.0/0\trefuse
\taccess-control: ::/0\trefuse
\taccess-control: ${PRIVATE_SUBNET_V4}\tallow
\taccess-control: ${PRIVATE_SUBNET_V6}\tallow
\taccess-control: 127.0.0.1\tallow
\taccess-control: ::1\tallow
\tprivate-address: ${PRIVATE_SUBNET_V4}
\tprivate-address: ${PRIVATE_SUBNET_V6}
\tprivate-address: 10.0.0.0/8
\tprivate-address: 127.0.0.0/8
\tprivate-address: 169.254.0.0/16
\tprivate-address: 172.16.0.0/12
\tprivate-address: 192.168.0.0/16
\tprivate-address: ::ffff:0:0/96
\tprivate-address: fd00::/8
\tprivate-address: fe80::/10
\tdo-ip4: yes
\tdo-ip6: yes
\tdo-udp: yes
\tdo-tcp: yes
\tchroot: \"\"
\thide-identity: yes
\thide-version: yes
\tharden-glue: yes
\tharden-dnssec-stripped: yes
\tharden-referral-path: yes
\tunwanted-reply-threshold: 10000000
\tcache-min-ttl: 0
\tcache-max-ttl: 2592000
\tprefetch: yes
\tqname-minimisation: yes
\tprefetch-key: yes"
      echo -e "${UNBOUND_TEMP_INTERFACE_INFO}" | awk '!seen[$0]++' >${UNBOUND_CONFIG}
      # Without a root hints file Unbound refuses to start; let it use its built-in hints instead.
      if [ ! -s "${UNBOUND_ROOT_HINTS}" ]; then
        sed --in-place '/^[[:space:]]*root-hints:/d' "${UNBOUND_CONFIG}"
      fi
      # Configure block list if INSTALL_BLOCK_LIST is true.
      if [ "${INSTALL_BLOCK_LIST}" == true ]; then
        echo -e "\tinclude: ${UNBOUND_CONFIG_HOST}" >>${UNBOUND_CONFIG}
        if [ ! -d "${UNBOUND_CONFIG_DIRECTORY}" ]; then
          mkdir --parents "${UNBOUND_CONFIG_DIRECTORY}"
        fi
        update-content-blocker
        # The include must point at an existing file, even if the download failed.
        if [ ! -f "${UNBOUND_CONFIG_HOST}" ]; then
          : >"${UNBOUND_CONFIG_HOST}"
        fi
      fi
      # Update ownership of Unbound's root directory.
      # Update the resolv.conf file to use Unbound.
      if [ -f "${RESOLV_CONFIG_OLD}" ]; then
        rm --force ${RESOLV_CONFIG_OLD}
      fi
      if [ -f "${RESOLV_CONFIG}" ]; then
        chattr -i ${RESOLV_CONFIG}
        mv ${RESOLV_CONFIG} ${RESOLV_CONFIG_OLD}
      fi
      echo "nameserver 127.0.0.1" >${RESOLV_CONFIG}
      echo "nameserver ::1" >>${RESOLV_CONFIG}
      chattr +i ${RESOLV_CONFIG}
      # Save Unbound status to UNBOUND_MANAGER file.
      echo "Unbound: true" >${UNBOUND_MANAGER}
      # Set CLIENT_DNS to use gateway addresses.
      CLIENT_DNS="${GATEWAY_ADDRESS_V4},${GATEWAY_ADDRESS_V6}"
    fi
  }

  # Call the function to install Unbound.
  install-unbound

  # Function to configure WireGuard settings
  function wireguard-setconf() {
    # Generate server private and public keys
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}" | wg pubkey)
    # Generate client private and public keys
    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "${CLIENT_PRIVKEY}" | wg pubkey)
    # Assign client IPv4 and IPv6 addresses
    CLIENT_ADDRESS_V4=$(echo "${PRIVATE_SUBNET_V4}" | cut --delimiter="." --fields=1-3).2
    CLIENT_ADDRESS_V6=$(echo "${PRIVATE_SUBNET_V6}" | cut --delimiter=":" --fields=1-4):2
    # Generate a pre-shared key for the client
    PRESHARED_KEY=$(wg genpsk)
    # Create the wireguard directory
    mkdir --parents ${WIREGUARD_PATH}
    # Create the client configuration directory
    mkdir --parents ${WIREGUARD_CLIENT_PATH}
    # Set up nftables rules depending on whether Unbound is installed
    if [ "${INSTALL_UNBOUND}" == true ]; then
      # Set up nftables rules for when Unbound is installed
      NFTABLES_POSTUP="nft add table inet wireguard-${WIREGUARD_PUB_NIC}; nft add chain inet wireguard-${WIREGUARD_PUB_NIC} wireguard_chain {type nat hook postrouting priority srcnat\;}; nft add rule inet wireguard-${WIREGUARD_PUB_NIC} wireguard_chain oifname ${SERVER_PUB_NIC} masquerade"
      NFTABLES_POSTDOWN="nft delete table inet wireguard-${WIREGUARD_PUB_NIC}"
    else
      # Set up nftables rules for when Unbound is not installed
      NFTABLES_POSTUP="nft add table inet wireguard-${WIREGUARD_PUB_NIC}; nft add chain inet wireguard-${WIREGUARD_PUB_NIC} PREROUTING {type nat hook prerouting priority 0\;}; nft add chain inet wireguard-${WIREGUARD_PUB_NIC} POSTROUTING {type nat hook postrouting priority 100\;}; nft add rule inet wireguard-${WIREGUARD_PUB_NIC} POSTROUTING ip saddr ${PRIVATE_SUBNET_V4} oifname ${SERVER_PUB_NIC} masquerade; nft add rule inet wireguard-${WIREGUARD_PUB_NIC} POSTROUTING ip6 saddr ${PRIVATE_SUBNET_V6} oifname ${SERVER_PUB_NIC} masquerade"
      NFTABLES_POSTDOWN="nft delete table inet wireguard-${WIREGUARD_PUB_NIC}"
    fi
    # If iptables is present, let wg traffic through a FORWARD policy of DROP (Docker, ufw).
    if [ -x "$(command -v iptables)" ]; then
      NFTABLES_POSTUP="${NFTABLES_POSTUP}; iptables -w 5 -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT; iptables -w 5 -I FORWARD -i ${WIREGUARD_PUB_NIC} -j ACCEPT; iptables -w 5 -I FORWARD -o ${WIREGUARD_PUB_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
      NFTABLES_POSTDOWN="${NFTABLES_POSTDOWN}; iptables -w 5 -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT; iptables -w 5 -D FORWARD -i ${WIREGUARD_PUB_NIC} -j ACCEPT; iptables -w 5 -D FORWARD -o ${WIREGUARD_PUB_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    fi
    if [ -x "$(command -v ip6tables)" ]; then
      NFTABLES_POSTUP="${NFTABLES_POSTUP}; ip6tables -w 5 -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT; ip6tables -w 5 -I FORWARD -i ${WIREGUARD_PUB_NIC} -j ACCEPT; ip6tables -w 5 -I FORWARD -o ${WIREGUARD_PUB_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
      NFTABLES_POSTDOWN="${NFTABLES_POSTDOWN}; ip6tables -w 5 -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT; ip6tables -w 5 -D FORWARD -i ${WIREGUARD_PUB_NIC} -j ACCEPT; ip6tables -w 5 -D FORWARD -o ${WIREGUARD_PUB_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    fi
    # Enable forwarding persistently instead of toggling it host-wide on every up/down.
    printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' >"${WIREGUARD_SYSCTL_CONFIG}"
    sysctl --load="${WIREGUARD_SYSCTL_CONFIG}"
    # Create server WireGuard configuration file
    echo "# ${PRIVATE_SUBNET_V4} ${PRIVATE_SUBNET_V6} ${SERVER_HOST}:${SERVER_PORT} ${SERVER_PUBKEY} ${CLIENT_DNS} ${PEER_MTU_CHOICE} ${NAT_CHOICE} ${CLIENT_ALLOWED_IP}
[Interface]
Address = ${GATEWAY_ADDRESS_V4}/${PRIVATE_SUBNET_MASK_V4},${GATEWAY_ADDRESS_V6}/${PRIVATE_SUBNET_MASK_V6}
ListenPort = ${SERVER_PORT}
MTU = ${INTERFACE_MTU_CHOICE}
PrivateKey = ${SERVER_PRIVKEY}
PostUp = ${NFTABLES_POSTUP}
PostDown = ${NFTABLES_POSTDOWN}
SaveConfig = false
# ${CLIENT_NAME} start
[Peer]
PublicKey = ${CLIENT_PUBKEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${CLIENT_ADDRESS_V4}/32,${CLIENT_ADDRESS_V6}/128
# ${CLIENT_NAME} end" >>${WIREGUARD_CONFIG}

    # Client MTU: only set when a custom value was chosen.
    if [ "${PEER_MTU_CHOICE}" == "auto" ]; then
      CLIENT_MTU_LINE="# MTU = 1420 (uncomment and lower, e.g. to 1280, only if large transfers stall)"
    else
      CLIENT_MTU_LINE="MTU = ${PEER_MTU_CHOICE}"
    fi
    # Generate client-specific WireGuard configuration file
    echo "# ${WIREGUARD_WEBSITE_URL}
[Interface]
Address = ${CLIENT_ADDRESS_V4}/32,${CLIENT_ADDRESS_V6}/128
DNS = ${CLIENT_DNS}
${CLIENT_MTU_LINE}
PrivateKey = ${CLIENT_PRIVKEY}
[Peer]
AllowedIPs = ${CLIENT_ALLOWED_IP}
Endpoint = ${SERVER_HOST}:${SERVER_PORT}
PersistentKeepalive = ${NAT_CHOICE}
PresharedKey = ${PRESHARED_KEY}
PublicKey = ${SERVER_PUBKEY}" >>${WIREGUARD_CLIENT_PATH}/"${CLIENT_NAME}".conf
    # Update ownership of the WireGuard configuration directory to root
    chown --recursive root:root ${WIREGUARD_PATH}
    # Apply appropriate permissions to the WireGuard configuration directory
    find ${WIREGUARD_PATH} -type d -exec chmod 700 {} +
    # Apply appropriate permissions to the WireGuard configuration files
    find ${WIREGUARD_PATH} -type f -exec chmod 600 {} +
    # Schedule automatic WireGuard expiration if enabled
    if [ "${AUTOMATIC_WIREGUARD_EXPIRATION}" == true ]; then
      crontab -l 2>/dev/null | {
        cat
        echo "$(date +%M) $(date +%H) $(date +%d) $(date +%m) * echo -e \"${CLIENT_NAME}\" | ${CURRENT_FILE_PATH} --remove"
      } | crontab -
    fi
    # Initiate and set the necessary services to run at startup, depending on the init system (either systemd or init)
    if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
      systemctl enable --now wg-quick@${WIREGUARD_PUB_NIC}
      if [ "${INSTALL_UNBOUND}" == true ]; then
        systemctl enable --now unbound
        systemctl restart unbound
      fi
    elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
      service wg-quick@${WIREGUARD_PUB_NIC} start
      if [ "${INSTALL_UNBOUND}" == true ]; then
        service unbound restart
      fi
    fi
    # Check that the tunnel actually came up.
    if wg show "${WIREGUARD_PUB_NIC}" >/dev/null 2>&1; then
      echo "WireGuard is running on ${WIREGUARD_PUB_NIC}."
    else
      echo "WARNING: WireGuard does not seem to be running on ${WIREGUARD_PUB_NIC}."
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        echo "Check it with: systemctl status wg-quick@${WIREGUARD_PUB_NIC} and journalctl -u wg-quick@${WIREGUARD_PUB_NIC}"
      fi
      echo "If you see \"Cannot find device ${WIREGUARD_PUB_NIC}\", the kernel was probably updated: reboot and run this script again."
    fi
    # Create a QR code for the client configuration for easy scanning
    qrencode -t ansiutf8 <${WIREGUARD_CLIENT_PATH}/"${CLIENT_NAME}".conf
    # Display the client configuration details in the terminal
    cat ${WIREGUARD_CLIENT_PATH}/"${CLIENT_NAME}".conf
    # Show the path where the client configuration file is stored
    echo "Client Config --> ${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf"
  }

  # Configuring WireGuard settings
  wireguard-setconf

# After WireGuard Install
else

  # Older versions named client configs <peer>-<interface>.conf; rename them to <peer>.conf once.
  if [ -d "${WIREGUARD_CLIENT_PATH}" ]; then
    for OLD_CLIENT_FILE in "${WIREGUARD_CLIENT_PATH}"/*-"${WIREGUARD_PUB_NIC}".conf; do
      [ -f "${OLD_CLIENT_FILE}" ] || continue
      NEW_CLIENT_FILE="${OLD_CLIENT_FILE%-"${WIREGUARD_PUB_NIC}".conf}.conf"
      [ -e "${NEW_CLIENT_FILE}" ] || mv "${OLD_CLIENT_FILE}" "${NEW_CLIENT_FILE}"
    done
  fi

  # What to do if the software is already installed?
  function wireguard-next-questions-interface() {
    echo "Please select an action:"
    echo "   1) Display WireGuard configuration"
    echo "   2) Initiate WireGuard service"
    echo "   3) Terminate WireGuard service"
    echo "   4) Restart WireGuard service"
    echo "   5) Add a new WireGuard peer (client)"
    echo "   6) Remove a WireGuard peer (client)"
    echo "   7) Reinstall WireGuard service"
    echo "   8) Uninstall WireGuard service"
    echo "   9) Update this management script"
    echo "   10) Backup WireGuard configuration"
    echo "   11) Restore WireGuard configuration"
    echo "   12) Update WireGuard interface IP"
    echo "   13) Update WireGuard interface port"
    echo "   14) Purge all WireGuard peers"
    echo "   15) Generate a QR code for WireGuard configuration"
    echo "   16) Verify WireGuard configurations"
    until [[ "${WIREGUARD_OPTIONS}" =~ ^[0-9]+$ ]] && [ "${WIREGUARD_OPTIONS}" -ge 1 ] && [ "${WIREGUARD_OPTIONS}" -le 16 ]; do
      read -rp "Select an Option [1-16]:" -e -i 0 WIREGUARD_OPTIONS
    done
    case ${WIREGUARD_OPTIONS} in
    1) # Display WireGuard configuration
      wg show ${WIREGUARD_PUB_NIC}
      ;;
    2) # Initiate WireGuard service
      wg-quick up ${WIREGUARD_PUB_NIC}
      ;;
    3) # Terminate WireGuard service
      wg-quick down ${WIREGUARD_PUB_NIC}
      ;;
    4) # Restart the WireGuard service
      # The script first identifies the init system (either "systemd" or "init")
      # Then, it restarts the WireGuard service based on the identified init system
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl restart wg-quick@${WIREGUARD_PUB_NIC}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} restart
      fi
      ;;
    5) # Adding a new peer to WireGuard
      # If a client name isn't supplied, the script will request one
      if [ -z "${NEW_CLIENT_NAME}" ]; then
        echo "Let's name the WireGuard Peer. Use one word only, no special characters, no spaces."
        read -rp "New client peer:" -e -i "$(next-peer-name)" NEW_CLIENT_NAME
      fi
      # If no client name is provided, use openssl to generate a random name
      if [ -z "${NEW_CLIENT_NAME}" ]; then
        NEW_CLIENT_NAME="$(next-peer-name)"
      fi
      validate-peer-name "${NEW_CLIENT_NAME}"
      if grep -q "^# ${NEW_CLIENT_NAME} start$" "${WIREGUARD_CONFIG}"; then
        echo "Error: A peer named ${NEW_CLIENT_NAME} already exists."
        exit 1
      fi
      # Extract the last IPv4 address used in the WireGuard configuration file
      LASTIPV4=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="/" --fields=1 | cut --delimiter="." --fields=4 | sort --numeric-sort | tail --lines=1)
      # Extract the last IPv6 address used in the WireGuard configuration file
      LASTIPV6=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="," --fields=2 | cut --delimiter="/" --fields=1 | cut --delimiter=":" --fields=5 | sort --numeric-sort | tail --lines=1)
      # If no IPv4 and IPv6 addresses are found in the configuration file, set the initial values to 1
      if { [ -z "${LASTIPV4}" ] && [ -z "${LASTIPV6}" ]; }; then
        LASTIPV4=1
        LASTIPV6=1
      fi
      # Find the smallest used IPv4 address in the WireGuard configuration file
      # Start the gap search at .2 (.1 is the server) so a freed .2 is reused too.
      SMALLEST_USED_IPV4=2
      # Find the largest used IPv4 address in the WireGuard configuration file
      LARGEST_USED_IPV4=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="/" --fields=1 | cut --delimiter="." --fields=4 | sort --numeric-sort | tail --lines=1)
      # Create a list of used IPv4 addresses in the WireGuard configuration file
      USED_IPV4_LIST=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="/" --fields=1 | cut --delimiter="." --fields=4 | sort --numeric-sort)
      # Loop through IPv4 addresses and find an unused one
      while [ "${SMALLEST_USED_IPV4}" -le "${LARGEST_USED_IPV4}" ]; do
        if ! grep --quiet --line-regexp "${SMALLEST_USED_IPV4}" <<<"${USED_IPV4_LIST}"; then
          FIND_UNUSED_IPV4=${SMALLEST_USED_IPV4}
          break
        fi
        SMALLEST_USED_IPV4=$((SMALLEST_USED_IPV4 + 1))
      done
      # Find the smallest used IPv6 address in the WireGuard configuration file
      SMALLEST_USED_IPV6=2
      # Find the largest used IPv6 address in the WireGuard configuration file
      LARGEST_USED_IPV6=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="," --fields=2 | cut --delimiter="/" --fields=1 | cut --delimiter=":" --fields=5 | sort --numeric-sort | tail --lines=1)
      # Create a list of used IPv6 addresses in the WireGuard configuration file
      USED_IPV6_LIST=$(grep "AllowedIPs" ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3 | cut --delimiter="," --fields=2 | cut --delimiter="/" --fields=1 | cut --delimiter=":" --fields=5 | sort --numeric-sort)
      # Loop through IPv6 addresses and find an unused one
      while [ "${SMALLEST_USED_IPV6}" -le "${LARGEST_USED_IPV6}" ]; do
        if ! grep --quiet --line-regexp "${SMALLEST_USED_IPV6}" <<<"${USED_IPV6_LIST}"; then
          FIND_UNUSED_IPV6=${SMALLEST_USED_IPV6}
          break
        fi
        SMALLEST_USED_IPV6=$((SMALLEST_USED_IPV6 + 1))
      done
      # If unused IPv4 and IPv6 addresses are found, set them as the last IPv4 and IPv6 addresses
      if { [ -n "${FIND_UNUSED_IPV4}" ] && [ -n "${FIND_UNUSED_IPV6}" ]; }; then
        LASTIPV4=$(echo "${FIND_UNUSED_IPV4}" | head --lines=1)
        LASTIPV6=$(echo "${FIND_UNUSED_IPV6}" | head --lines=1)
      fi
      # The /24 tunnel subnet holds .2 to .254; stop instead of handing out addresses outside it.
      if [ -z "${FIND_UNUSED_IPV4}" ] && [ "${LASTIPV4}" -ge 254 ]; then
        echo "Error: The tunnel subnet is full (253 peers). Remove a peer first."
        exit 1
      fi
      # Generate a private key for the client
      CLIENT_PRIVKEY=$(wg genkey)
      # Derive the public key from the private key
      CLIENT_PUBKEY=$(echo "${CLIENT_PRIVKEY}" | wg pubkey)
      # Generate a preshared key for the client and server to use
      PRESHARED_KEY=$(wg genpsk)
      # Get the private subnet and subnet mask from the WireGuard config file
      PRIVATE_SUBNET_V4=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2)
      PRIVATE_SUBNET_MASK_V4=$(echo "${PRIVATE_SUBNET_V4}" | cut --delimiter="/" --fields=2)
      PRIVATE_SUBNET_V6=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=3)
      PRIVATE_SUBNET_MASK_V6=$(echo "${PRIVATE_SUBNET_V6}" | cut --delimiter="/" --fields=2)
      # Get the server host and public key from the WireGuard config file
      SERVER_HOST=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=4)
      SERVER_PUBKEY=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=5)
      # Get the client DNS server, MTU choice, NAT choice, and allowed IP address from the WireGuard config file
      CLIENT_DNS=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=6)
      MTU_CHOICE=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=7)
      NAT_CHOICE=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=8)
      CLIENT_ALLOWED_IP=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=9)
      # Calculate the client's IP addresses based on the last IP addresses used
      CLIENT_ADDRESS_V4=$(echo "${PRIVATE_SUBNET_V4}" | cut --delimiter="." --fields=1-3).$((LASTIPV4 + 1))
      CLIENT_ADDRESS_V6=$(echo "${PRIVATE_SUBNET_V6}" | cut --delimiter=":" --fields=1-4):$((LASTIPV6 + 1))
      # Check if there are any unused IP addresses available
      if { [ -n "${FIND_UNUSED_IPV4}" ] && [ -n "${FIND_UNUSED_IPV6}" ]; }; then
        CLIENT_ADDRESS_V4=$(echo "${CLIENT_ADDRESS_V4}" | cut --delimiter="." --fields=1-3).${LASTIPV4}
        CLIENT_ADDRESS_V6=$(echo "${CLIENT_ADDRESS_V6}" | cut --delimiter=":" --fields=1-4):${LASTIPV6}
      fi
      # Create a temporary file to store the new client information
      WIREGUARD_TEMP_NEW_CLIENT_INFO="# ${NEW_CLIENT_NAME} start
[Peer]
PublicKey = ${CLIENT_PUBKEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${CLIENT_ADDRESS_V4}/32,${CLIENT_ADDRESS_V6}/128
# ${NEW_CLIENT_NAME} end"
      # Write the temporary new client information to the 'add peer' configuration file
      echo "${WIREGUARD_TEMP_NEW_CLIENT_INFO}" >${WIREGUARD_ADD_PEER_CONFIG}
      # Add the new peer configuration to the WireGuard interface
      wg addconf ${WIREGUARD_PUB_NIC} ${WIREGUARD_ADD_PEER_CONFIG}
      # If there are no unused IPv4 and IPv6 addresses, append the new client information to the WireGuard configuration file
      # Peer order is irrelevant to WireGuard, so always append (the old line-offset insert corrupted peer blocks).
      echo "${WIREGUARD_TEMP_NEW_CLIENT_INFO}" >>${WIREGUARD_CONFIG}
      # Remove the wireguard add peer config file
      rm --force ${WIREGUARD_ADD_PEER_CONFIG}
      # Client MTU: only set when a custom value was chosen at install.
      if [ "${MTU_CHOICE}" == "auto" ]; then
        CLIENT_MTU_LINE="# MTU = 1420 (uncomment and lower, e.g. to 1280, only if large transfers stall)"
      else
        CLIENT_MTU_LINE="MTU = ${MTU_CHOICE}"
      fi
      # Create the client configuration file
      echo "# ${WIREGUARD_WEBSITE_URL}
[Interface]
Address = ${CLIENT_ADDRESS_V4}/32,${CLIENT_ADDRESS_V6}/128
DNS = ${CLIENT_DNS}
${CLIENT_MTU_LINE}
PrivateKey = ${CLIENT_PRIVKEY}
[Peer]
AllowedIPs = ${CLIENT_ALLOWED_IP}
Endpoint = ${SERVER_HOST}
PersistentKeepalive = ${NAT_CHOICE}
PresharedKey = ${PRESHARED_KEY}
PublicKey = ${SERVER_PUBKEY}" >>${WIREGUARD_CLIENT_PATH}/"${NEW_CLIENT_NAME}".conf
      # Add the WireGuard interface configuration, stripping any unnecessary fields
      wg syncconf ${WIREGUARD_PUB_NIC} <(wg-quick strip ${WIREGUARD_PUB_NIC})
      # Check if automatic WireGuard expiration is enabled, and if so, set the expiration date
      if crontab -l | grep -q "${CURRENT_FILE_PATH} --remove"; then
        crontab -l 2>/dev/null | {
          cat
          # Add a new cron job to remove the new client at the specified expiration date
          echo "$(date +%M) $(date +%H) $(date +%d) $(date +%m) * echo -e \"${NEW_CLIENT_NAME}\" | ${CURRENT_FILE_PATH} --remove"
        } | crontab -
      fi
      # Generate and display a QR code for the new client configuration
      qrencode -t ansiutf8 <${WIREGUARD_CLIENT_PATH}/"${NEW_CLIENT_NAME}".conf
      # Output the new client configuration file content
      cat ${WIREGUARD_CLIENT_PATH}/"${NEW_CLIENT_NAME}".conf
      # Display the path of the new client configuration file
      echo "Client config --> ${WIREGUARD_CLIENT_PATH}/${NEW_CLIENT_NAME}.conf"
      ;;
    6) # Remove WireGuard Peer
      # Prompt the user to choose a WireGuard peer to remove
      echo "Which WireGuard peer would you like to remove?"
      # List all the peers' names in the WireGuard configuration file
      grep start ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2
      # Read the user input for the peer's name
      read -rp "Peer's name:" REMOVECLIENT
      validate-peer-name "${REMOVECLIENT}"
      if ! grep -q "^# ${REMOVECLIENT} start$" "${WIREGUARD_CONFIG}"; then
        echo "Error: No peer named ${REMOVECLIENT} found."
        exit 1
      fi
      # Extract the public key of the selected peer from the configuration file
      CLIENTKEY=$(sed -n "/\# ${REMOVECLIENT} start/,/\# ${REMOVECLIENT} end/p" ${WIREGUARD_CONFIG} | grep PublicKey | cut --delimiter=" " --fields=3)
      # Remove the selected peer from the WireGuard interface using the extracted public key
      wg set ${WIREGUARD_PUB_NIC} peer "${CLIENTKEY}" remove
      # Remove the selected peer's configuration block from the WireGuard configuration file
      sed --in-place "/\# ${REMOVECLIENT} start/,/\# ${REMOVECLIENT} end/d" ${WIREGUARD_CONFIG}
      # If the selected peer has a configuration file in the client path, remove it
      if [ -f "${WIREGUARD_CLIENT_PATH}/${REMOVECLIENT}.conf" ]; then
        rm --force ${WIREGUARD_CLIENT_PATH}/"${REMOVECLIENT}".conf
      fi
      # Reload the WireGuard interface configuration to apply the changes
      wg syncconf ${WIREGUARD_PUB_NIC} <(wg-quick strip ${WIREGUARD_PUB_NIC})
      # Remove any cronjobs associated with the removed peer
      crontab -l 2>/dev/null | grep --invert-match --fixed-strings "echo -e \"${REMOVECLIENT}\" |" | crontab -
      ;;
    7) # Reinstall WireGuard
      # Check if the current init system is systemd, and if so, disable and stop the WireGuard service
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl disable --now wg-quick@${WIREGUARD_PUB_NIC}
      # Check if the current init system is init, and if so, stop the WireGuard service
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} stop
      fi
      # Bring down the WireGuard interface
      wg-quick down ${WIREGUARD_PUB_NIC}
      # Reinstall or update WireGuard based on the current Linux distribution
      if { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        dpkg-reconfigure wireguard-dkms
        modprobe wireguard
      elif { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        yum reinstall wireguard-tools -y
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Su --noconfirm wireguard-tools
      elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
        apk fix wireguard-tools
      elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
        pkg check wireguard
      elif [ "${CURRENT_DISTRO}" == "ol" ]; then
        yum reinstall wireguard-tools -y
      fi
      # Enable and start the WireGuard service based on the current init system
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl enable --now wg-quick@${WIREGUARD_PUB_NIC}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} restart
      fi
      ;;
    8) # Uninstall WireGuard and purging files
      # Check if the current init system is systemd and disable the WireGuard service
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl disable --now wg-quick@${WIREGUARD_PUB_NIC}
        # If the init system is not systemd, check if it is init and stop the WireGuard service
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} stop
      fi
      # Bring down the WireGuard interface
      wg-quick down ${WIREGUARD_PUB_NIC}
      # Removing Wireguard Files
      # Check if the WireGuard directory exists and remove it
      if [ -d "${WIREGUARD_PATH}" ]; then
        rm --recursive --force ${WIREGUARD_PATH}
      fi
      # Remove WireGuard and qrencode packages based on the current distribution
      # For CentOS, AlmaLinux, and Rocky Linux distributions
      if { [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
        yum remove wireguard qrencode -y
        # For Ubuntu, Debian, Raspbian, Pop!_OS, Kali Linux, Linux Mint, and KDE Neon distributions
      elif { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
        apt-get remove --purge wireguard qrencode -y
        # Remove backports repository and keys if they exist
        if [ -f "/etc/apt/sources.list.d/backports.list" ]; then
          rm --force /etc/apt/sources.list.d/backports.list
          apt-key del 648ACFD622F3D138
          apt-key del 0E98404D386FA1D9
        fi
        # For Arch, Arch ARM, and Manjaro distributions
      elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
        pacman -Rs --noconfirm wireguard-tools qrencode
        # For Fedora distribution
      elif [ "${CURRENT_DISTRO}" == "fedora" ]; then
        dnf remove wireguard qrencode -y
        # Remove WireGuard repository if it exists
        if [ -f "/etc/yum.repos.d/wireguard.repo" ]; then
          rm --force /etc/yum.repos.d/wireguard.repo
        fi
        # For RHEL distribution
      elif [ "${CURRENT_DISTRO}" == "rhel" ]; then
        yum remove wireguard qrencode -y
        # Remove WireGuard repository if it exists
        if [ -f "/etc/yum.repos.d/wireguard.repo" ]; then
          rm --force /etc/yum.repos.d/wireguard.repo
        fi
        # For Alpine Linux distribution
      elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
        apk del wireguard-tools libqrencode
        # For FreeBSD distribution
      elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
        pkg delete wireguard libqrencode
      # For Oracle Linux distribution
      elif [ "${CURRENT_DISTRO}" == "ol" ]; then
        yum remove wireguard qrencode -y
      fi
      # Remove the forwarding drop-in. Runtime forwarding is left as is so Docker or other
      # tunnels on this host keep working; it returns to the system default on the next reboot.
      if [ -f "${WIREGUARD_SYSCTL_CONFIG}" ]; then
        rm --force "${WIREGUARD_SYSCTL_CONFIG}"
        echo "Removed ${WIREGUARD_SYSCTL_CONFIG}."
      fi
      # Delete WireGuard backup
      if [ -f "${WIREGUARD_CONFIG_BACKUP}" ]; then
        rm --force ${WIREGUARD_CONFIG_BACKUP}
        if [ -f "${WIREGUARD_BACKUP_PASSWORD_PATH}" ]; then
          rm --force "${WIREGUARD_BACKUP_PASSWORD_PATH}"
        fi
      fi
      # Uninstall unbound
      # Check if the 'unbound' command is available on the system
      if [ -x "$(command -v unbound)" ]; then
        # Check if the current init system is systemd and disable the Unbound service
        if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
          systemctl disable --now unbound
        # If the init system is not systemd, check if it is init and stop the Unbound service
        elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
          service unbound stop
        fi
        # If a backup of the resolv.conf file exists, restore it and set the immutable flag
        if [ -f "${RESOLV_CONFIG_OLD}" ]; then
          chattr -i ${RESOLV_CONFIG}
          rm --force ${RESOLV_CONFIG}
          mv ${RESOLV_CONFIG_OLD} ${RESOLV_CONFIG}
        fi
        # Remove Unbound package based on the current distribution
        # For CentOS, RHEL, AlmaLinux, and Rocky Linux distributions
        if { [ "${CURRENT_DISTRO}" == "centos" ] || [ "${CURRENT_DISTRO}" == "rhel" ] || [ "${CURRENT_DISTRO}" == "almalinux" ] || [ "${CURRENT_DISTRO}" == "rocky" ]; }; then
          yum remove unbound -y
        # For Ubuntu, Debian, Raspbian, Pop!_OS, Kali Linux, Linux Mint, and KDE Neon distributions
        elif { [ "${CURRENT_DISTRO}" == "ubuntu" ] || [ "${CURRENT_DISTRO}" == "debian" ] || [ "${CURRENT_DISTRO}" == "raspbian" ] || [ "${CURRENT_DISTRO}" == "pop" ] || [ "${CURRENT_DISTRO}" == "kali" ] || [ "${CURRENT_DISTRO}" == "linuxmint" ] || [ "${CURRENT_DISTRO}" == "neon" ]; }; then
          # If the distribution is Ubuntu, restart systemd-resolved service based on the init system
          if [ "${CURRENT_DISTRO}" == "ubuntu" ]; then
            if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
              systemctl enable --now systemd-resolved
            elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
              service systemd-resolved restart
            fi
          fi
          apt-get remove --purge unbound -y
        # For Arch, Arch ARM, and Manjaro distributions
        elif { [ "${CURRENT_DISTRO}" == "arch" ] || [ "${CURRENT_DISTRO}" == "archarm" ] || [ "${CURRENT_DISTRO}" == "manjaro" ]; }; then
          pacman -Rs --noconfirm unbound
        # For Fedora and Oracle Linux distributions
        elif { [ "${CURRENT_DISTRO}" == "fedora" ] || [ "${CURRENT_DISTRO}" == "ol" ]; }; then
          yum remove unbound -y
        # For Alpine Linux distribution
        elif [ "${CURRENT_DISTRO}" == "alpine" ]; then
          apk del unbound
        # For FreeBSD distribution
        elif [ "${CURRENT_DISTRO}" == "freebsd" ]; then
          pkg delete unbound
        fi
        # Remove Unbound root directory if it exists
        if [ -d "${UNBOUND_ROOT}" ]; then
          rm --recursive --force ${UNBOUND_ROOT}
        fi
        # Remove Unbound root anchor file if it exists
        if [ -f "${UNBOUND_ANCHOR}" ]; then
          rm --force ${UNBOUND_ANCHOR}
        fi
      fi
      # If any cronjobs are identified, they should be removed.
      crontab -l 2>/dev/null | grep --invert-match --fixed-strings "${CURRENT_FILE_PATH}" | crontab -
      ;;
    9) # Update WireGuard Manager script.
      # Calculate the SHA3-512 hash of the current WireGuard Manager script
      CURRENT_WIREGUARD_MANAGER_HASH=$(openssl dgst -sha3-512 "${CURRENT_FILE_PATH}" | cut --delimiter=" " --fields=2)
      # Calculate the SHA3-512 hash of the latest WireGuard Manager script from the remote source
      NEW_WIREGUARD_MANAGER_HASH=$(curl --silent "${WIREGUARD_MANAGER_UPDATE}" | openssl dgst -sha3-512 | cut --delimiter=" " --fields=2)
      # If the hashes don't match, update the local WireGuard Manager script
      if [ "${CURRENT_WIREGUARD_MANAGER_HASH}" != "${NEW_WIREGUARD_MANAGER_HASH}" ]; then
        UPDATE_TMP=$(mktemp)
        if curl --fail --silent --show-error --location "${WIREGUARD_MANAGER_UPDATE}" -o "${UPDATE_TMP}" && bash -n "${UPDATE_TMP}"; then
          mv "${UPDATE_TMP}" "${CURRENT_FILE_PATH}"
          chmod +x "${CURRENT_FILE_PATH}"
          echo "Updating WireGuard Manager script..."
        else
          rm --force "${UPDATE_TMP}"
          echo "Warning: Update download failed or did not pass a syntax check, keeping current script."
        fi
      fi
      # Update the unbound configs if the unbound command is available on the system
      if [ -x "$(command -v unbound)" ]; then
        # Update the unbound root hints file if it exists
        if [ -f "${UNBOUND_ROOT_HINTS}" ] && update-root-hints; then
          echo "Updating root hints file..."
        fi
        # Update the unbound content-blocker file if it exists
        if [ -f "${UNBOUND_CONFIG_HOST}" ] && update-content-blocker; then
          echo "Updating unbound config host file..."
        fi
        # Once everything is completed, restart the unbound service (only if the config is valid)
        if ! unbound-checkconf "${UNBOUND_CONFIG}" >/dev/null 2>&1; then
          echo "Error: Unbound config is invalid, not restarting unbound."
        elif [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
          systemctl restart unbound
          echo "Restarting unbound service..."
        elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
          service unbound restart
          echo "Restarting unbound service..."
        fi
      fi
      ;;
    10) # Backup WireGuard Config
      # If the WireGuard config backup file exists, remove it
      if [ -f "${WIREGUARD_CONFIG_BACKUP}" ]; then
        rm --force ${WIREGUARD_CONFIG_BACKUP}
        echo "Removing existing backup..."
      fi
      # If the system backup path directory does not exist, create it along with any necessary parent directories
      if [ ! -d "${SYSTEM_BACKUP_PATH}" ]; then
        mkdir --parents ${SYSTEM_BACKUP_PATH}
        echo "Creating backup directory..."
      fi
      # If the WireGuard path directory exists, proceed with the backup process
      if [ -d "${WIREGUARD_PATH}" ]; then
        # Generate a random 50-character hexadecimal backup password and store it in a file
        BACKUP_PASSWORD="$(openssl rand -hex 25)"
        (umask 077 && echo "${BACKUP_PASSWORD}" >"${WIREGUARD_BACKUP_PASSWORD_PATH}")
        # Zip the WireGuard config file using the generated backup password and save it as a backup
        (cd "${WIREGUARD_PATH}" && zip -P "${BACKUP_PASSWORD}" -r "${WIREGUARD_CONFIG_BACKUP}" "$(basename "${WIREGUARD_CONFIG}")" "$(basename "${WIREGUARD_CLIENT_PATH}")")
        chmod 600 "${WIREGUARD_CONFIG_BACKUP}"
        # Echo the backup password and path to the terminal
        echo "Backup Password: ${BACKUP_PASSWORD}"
        echo "Backup Path: ${WIREGUARD_CONFIG_BACKUP}"
        echo "Please save the backup password and path in a secure location."
      fi
      ;;
    11) # Restore WireGuard Config
      # Check if the WireGuard config backup file does not exist, and if so, exit the script
      if [ ! -f "${WIREGUARD_CONFIG_BACKUP}" ]; then
        echo "Error: The WireGuard configuration backup file could not be found. Please ensure it exists and try again."
        exit
      fi
      # Prompt the user to enter the backup password and store it in the WIREGUARD_BACKUP_PASSWORD variable
      read -rp "Backup Password: " -e -i "$(cat "${WIREGUARD_BACKUP_PASSWORD_PATH}")" WIREGUARD_BACKUP_PASSWORD
      # If the WIREGUARD_BACKUP_PASSWORD variable is empty, exit the script
      if [ -z "${WIREGUARD_BACKUP_PASSWORD}" ]; then
        echo "Error: The backup password field is empty. Please provide a valid password."
        exit
      fi
      # Unzip the backup file, overwriting existing files, using the specified backup password, and extract the contents to the WireGuard path
      unzip -o -P "${WIREGUARD_BACKUP_PASSWORD}" "${WIREGUARD_CONFIG_BACKUP}" -d "${WIREGUARD_PATH}"
      # If the current init system is systemd, enable and start the wg-quick service
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl enable --now wg-quick@${WIREGUARD_PUB_NIC}
      # If the current init system is init, restart the wg-quick service
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} restart
      fi
      ;;
    12) # Change the IP address of your wireguard interface.
      get-network-information
      # Extract the current IP address method from the WireGuard config file
      CURRENT_IP_METHORD=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=4)
      # If the current IP address method is IPv4, extract the old server host and set the new server host to DEFAULT_INTERFACE_IPV4
      if [[ ${CURRENT_IP_METHORD} != *"["* ]]; then
        OLD_SERVER_HOST=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=4 | cut --delimiter=":" --fields=1)
        NEW_SERVER_HOST=${DEFAULT_INTERFACE_IPV4}
      fi
      # If the current IP address method is IPv6, extract the old server host and set the new server host to DEFAULT_INTERFACE_IPV6
      if [[ ${CURRENT_IP_METHORD} == *"["* ]]; then
        OLD_SERVER_HOST=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=4 | cut --delimiter="[" --fields=2 | cut --delimiter="]" --fields=1)
        NEW_SERVER_HOST=${DEFAULT_INTERFACE_IPV6}
      fi
      # A hostname endpoint follows the server by itself; there is nothing to rewrite.
      if ! is-ipv4 "${OLD_SERVER_HOST}" && ! is-ipv6 "${OLD_SERVER_HOST}"; then
        echo "The endpoint is a hostname (${OLD_SERVER_HOST}), nothing to update."
        exit 0
      fi
      # If the current address is still assigned to this server, keep it (servers with several IPs).
      for LOCAL_PUBLIC_ADDRESS in "${LOCAL_PUBLIC_IPV4_LIST[@]}" "${LOCAL_PUBLIC_IPV6_LIST[@]}"; do
        if [ "${LOCAL_PUBLIC_ADDRESS}" == "${OLD_SERVER_HOST}" ]; then
          NEW_SERVER_HOST="${OLD_SERVER_HOST}"
        fi
      done
      if [ -z "${NEW_SERVER_HOST}" ]; then
        echo "Error: Could not detect the public IP address, leaving configuration unchanged."
        exit 1
      fi
      # If the old server host is different from the new server host, update the server host in the WireGuard config file
      if [ "${OLD_SERVER_HOST}" != "${NEW_SERVER_HOST}" ]; then
        sed --in-place "1s|${OLD_SERVER_HOST//./\\.}|${NEW_SERVER_HOST}|" ${WIREGUARD_CONFIG}
      fi
      # Create a list of existing WireGuard clients from the WireGuard config file
      COMPLETE_CLIENT_LIST=$(grep start ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2)
      # Add the clients to the USER_LIST array
      for CLIENT_LIST_ARRAY in ${COMPLETE_CLIENT_LIST}; do
        USER_LIST[ADD_CONTENT]=${CLIENT_LIST_ARRAY}
        ADD_CONTENT=$(("${ADD_CONTENT}" + 1))
      done
      # Loop through the clients in the USER_LIST array
      for CLIENT_NAME in "${USER_LIST[@]}"; do
        # Check if the client's config file exists
        if [ -f "${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf" ]; then
          # Update the server host in the client's config file
          sed --in-place "s|^Endpoint = ${OLD_SERVER_HOST//./\\.}|Endpoint = ${NEW_SERVER_HOST}|; s|^Endpoint = \\[${OLD_SERVER_HOST}\\]|Endpoint = [${NEW_SERVER_HOST}]|" "${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf"
        fi
      done
      ;;
    13) # Change the wireguard interface's port number.
      # Extract the old server port from the WireGuard config file
      OLD_SERVER_ENDPOINT=$(head --lines=1 ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=4)
      OLD_SERVER_PORT="${OLD_SERVER_ENDPOINT##*:}"
      # Prompt the user to enter a valid custom port (between 1 and 65535) and store it in NEW_SERVER_PORT
      until [[ "${NEW_SERVER_PORT}" =~ ^[0-9]+$ ]] && [ "${NEW_SERVER_PORT}" -ge 1 ] && [ "${NEW_SERVER_PORT}" -le 65535 ]; do
        read -rp "Enter a custom port number (between 1 and 65535): " -e -i 51820 NEW_SERVER_PORT
      done
      # Check if the chosen port is already in use by another application
      if [ "$(lsof -i UDP:"${NEW_SERVER_PORT}")" ]; then
        # If the port is in use, print an error message and exit the script
        echo "Error: The port number ${NEW_SERVER_PORT} is already in use by another application. Please try a different port number."
        exit
      fi
      # If the old server port is different from the new server port, update the server port in the WireGuard config file
      if [ "${OLD_SERVER_PORT}" == "${NEW_SERVER_PORT}" ]; then
        echo "The port is already ${NEW_SERVER_PORT}, nothing to change."
        exit 0
      fi
      # Stop first so PostDown removes the firewall rule for the old port.
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl stop wg-quick@${WIREGUARD_PUB_NIC}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} stop
      fi
      if [ "${OLD_SERVER_PORT}" != "${NEW_SERVER_PORT}" ]; then
        sed --in-place "s/^ListenPort = ${OLD_SERVER_PORT}$/ListenPort = ${NEW_SERVER_PORT}/; 1s/:${OLD_SERVER_PORT} /:${NEW_SERVER_PORT} /; s/--dport ${OLD_SERVER_PORT} /--dport ${NEW_SERVER_PORT} /g" ${WIREGUARD_CONFIG}
        echo "The server port has changed from ${OLD_SERVER_PORT} to ${NEW_SERVER_PORT} in ${WIREGUARD_CONFIG}."
      fi
      # Create a list of existing WireGuard clients from the WireGuard config file
      COMPLETE_CLIENT_LIST=$(grep start ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2)
      # Add the clients to the USER_LIST array
      for CLIENT_LIST_ARRAY in ${COMPLETE_CLIENT_LIST}; do
        USER_LIST[ADD_CONTENT]=${CLIENT_LIST_ARRAY}
        ADD_CONTENT=$(("${ADD_CONTENT}" + 1))
      done
      # Loop through the clients in the USER_LIST array
      for CLIENT_NAME in "${USER_LIST[@]}"; do
        # Check if the client's config file exists
        if [ -f "${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf" ]; then
          # Update the server port in the client's config file
          sed --in-place "s/^\\(Endpoint = .*\\):${OLD_SERVER_PORT}$/\\1:${NEW_SERVER_PORT}/" "${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf"
          echo "The server port has changed from ${OLD_SERVER_PORT} to ${NEW_SERVER_PORT} in ${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf."
        fi
      done
      # Bring the interface back up on the new port
      if [[ "${CURRENT_INIT_SYSTEM}" == *"systemd"* ]]; then
        systemctl start wg-quick@${WIREGUARD_PUB_NIC}
      elif [[ "${CURRENT_INIT_SYSTEM}" == *"init"* ]]; then
        service wg-quick@${WIREGUARD_PUB_NIC} start
      fi
      ;;
    14) # Remove all the peers from the interface.
      COMPLETE_CLIENT_LIST=$(grep start ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2)
      # This line gets the list of clients in the config file by searching for the string "start" and then extracting the second field (the client name) from each line.
      for CLIENT_LIST_ARRAY in ${COMPLETE_CLIENT_LIST}; do
        USER_LIST[ADD_CONTENT]=${CLIENT_LIST_ARRAY}
        ADD_CONTENT=$(("${ADD_CONTENT}" + 1))
      done
      # This loop iterates over each client in the list and adds it to an array called USER_LIST.
      for CLIENT_NAME in "${USER_LIST[@]}"; do
        CLIENTKEY=$(sed -n "/\# ${CLIENT_NAME} start/,/\# ${CLIENT_NAME} end/p" ${WIREGUARD_CONFIG} | grep PublicKey | cut --delimiter=" " --fields=3)
        # This line extracts the client's public key from the config file.
        wg set ${WIREGUARD_PUB_NIC} peer "${CLIENTKEY}" remove
        # This line removes the client from the server.
        sed --in-place "/\# ${CLIENT_NAME} start/,/\# ${CLIENT_NAME} end/d" ${WIREGUARD_CONFIG}
        # This line removes the client's config from the server.
        if [ -f "${WIREGUARD_CLIENT_PATH}/${CLIENT_NAME}.conf" ]; then
          rm --force ${WIREGUARD_CLIENT_PATH}/"${CLIENT_NAME}".conf
        else
          echo "The client config file for ${CLIENT_NAME} does not exist."
        fi
        # This line removes the client's config file from the server.
        wg syncconf ${WIREGUARD_PUB_NIC} <(wg-quick strip ${WIREGUARD_PUB_NIC})
        # This line removes the client's config from the running server.
        crontab -l 2>/dev/null | grep --invert-match --fixed-strings "echo -e \"${CLIENT_NAME}\" |" | crontab -
        # This line removes the client from the cron job.
      done
      ;;
    15) # Generate a QR code for a WireGuard peer.
      # Print a prompt asking the user to choose a WireGuard peer for generating a QR code
      echo "Which WireGuard peer would you like to generate a QR code for?"
      # Extract and display a list of peer names from the WireGuard config file
      grep start ${WIREGUARD_CONFIG} | cut --delimiter=" " --fields=2
      # Prompt the user to enter the desired peer's name and store it in the VIEW_CLIENT_INFO variable
      read -rp "Enter the name of the peer you want to view information for: " VIEW_CLIENT_INFO
      # Check if the config file for the specified peer exists
      if [ -f "${WIREGUARD_CLIENT_PATH}/${VIEW_CLIENT_INFO}.conf" ]; then
        # Generate a QR code for the specified peer's config file and display it in the terminal
        qrencode -t ansiutf8 <${WIREGUARD_CLIENT_PATH}/"${VIEW_CLIENT_INFO}".conf
        # Print the file path of the specified peer's config file
        echo "Peer's config --> ${WIREGUARD_CLIENT_PATH}/${VIEW_CLIENT_INFO}.conf"
      else
        # If the config file for the specified peer does not exist, print an error message
        echo "Error: The peer you specified could not be found. Please ensure you've entered the correct information."
        exit
      fi
      ;;
    16)
      # Check if the `unbound` command is available on the system by checking if it is executable
      if [ -x "$(command -v unbound)" ]; then
        # Check if the output of `unbound-checkconf` run on `UNBOUND_CONFIG` contains "no errors"
        if [[ "$(unbound-checkconf ${UNBOUND_CONFIG})" != *"no errors"* ]]; then
          # If "no errors" was not found in output of previous command, print an error message
          unbound-checkconf ${UNBOUND_CONFIG}
          echo "Error: We found an error on your unbound config file located at ${UNBOUND_CONFIG}"
          exit
        fi
        # Check if output of `unbound-host` run on `UNBOUND_CONFIG` with arguments `-C`, `-v`, and `cloudflare.com` contains "secure"
        if [[ "$(unbound-host -C ${UNBOUND_CONFIG} -v cloudflare.com)" != *"secure"* ]]; then
          # If "secure" was not found in output of previous command, print an error message
          unbound-host -C ${UNBOUND_CONFIG} -v cloudflare.com
          echo "Error: We found an error on your unbound DNS-SEC config file loacted at ${UNBOUND_CONFIG}"
          exit
        fi
        echo "Your unbound config file located at ${UNBOUND_CONFIG} is valid."
      fi
      # Check if the `wg` command is available on the system by checking if it is executable
      if [ -x "$(command -v wg)" ]; then
        # Check if the output of `wg` contains "interface" and "public key"
        if [[ "$(wg show ${WIREGUARD_PUB_NIC})" != *"interface"* ]] || [[ "$(wg show ${WIREGUARD_PUB_NIC})" != *"public key"* ]]; then
          # If "interface" and "public key" were not found in output of previous command, print an error message
          echo "Error: We found an error on your WireGuard interface."
          exit
        fi
        echo "Your WireGuard interface is valid."
      fi
      ;;
    esac
  }

  # Running Questions Command
  wireguard-next-questions-interface

fi