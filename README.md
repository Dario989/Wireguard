# Wireguard

Patched fork of [complexorganizations/wireguard-manager](https://github.com/complexorganizations/wireguard-manager) (MIT).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Dario989/Wireguard/main/wireguard-manager.sh -o /usr/local/bin/wireguard-manager.sh
chmod +x /usr/local/bin/wireguard-manager.sh
sudo bash /usr/local/bin/wireguard-manager.sh
```

Use a different interface name if `wg0` is already taken:

```bash
sudo WIREGUARD_PUB_NIC=wg1 bash /usr/local/bin/wireguard-manager.sh
```

## Changes from upstream

**Safety**
- Removing a peer no longer wipes root's crontab (empty or substring names used to match every cron line). Peer names are validated (`A-Z a-z 0-9 - _`) and must exist.
- Adding a peer always appends its block. The old gap-fill insert was off by one line and nested the new peer inside the next peer's markers.
- Gap detection compares whole numbers (`3` no longer matches `13`).
- Self-update only pulls from this repo, is syntax-checked before replacing the script, and is **off by default**.
- `nftables.service` is no longer enabled (Debian's `/etc/nftables.conf` runs `flush ruleset`, wiping iptables-nft, fail2ban and ipset rules).

**Networking**
- IP forwarding is set once in `/etc/sysctl.d/99-wireguard-manager.conf` instead of being turned off host-wide on `wg-quick down`.
- PostUp/PostDown add `FORWARD` accept rules (iptables/ip6tables) so clients work on hosts with a DROP forward policy (Docker, ufw).
- Interface name overridable via `WIREGUARD_PUB_NIC`.
- Peer changes reload with `wg syncconf` instead of `wg addconf`.

**Unbound**
- Root hints and blocklist download to a temp file with `curl --fail` and only replace the live file on success; a failed blocklist update is rolled back if `unbound-checkconf` fails, and Unbound is only restarted on a valid config.
- `cache-min-ttl` 86400 → 0 (records were cached for at least a day).
- `access-control: ::0` → `::/0`.

**Fixes**
- `--help` exits instead of starting the installer.
- Requirement check uses `crontab` (no `cron` binary on Arch/Fedora) and drops the unused `ifup`; `PATH` includes `/usr/sbin` so nightly cron runs don't reinstall packages.
- Cron entries are de-duplicated on re-run.
- Port change edits only `ListenPort`, the metadata line and `Endpoint` (it used to replace the number anywhere, including keys) and restarts the interface.
- DDNS refuses to write an empty IP when detection fails.
- Backup includes `clients/`; backup and password file are root-only.
- Uninstall no longer leaves the restored `resolv.conf` immutable.
- Verify option no longer executes command output, and checks the right interface.
