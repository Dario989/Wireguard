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

Use your own blocklist (plain domains or hosts format):

```bash
sudo CONTENT_BLOCKER_URL=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts bash /usr/local/bin/wireguard-manager.sh
```

## Changes from upstream

**Safety**
- Removing a peer no longer wipes root's crontab (empty or substring names used to match every cron line). Peer names are validated (`A-Z a-z 0-9 - _`) and must exist.
- Adding a peer always appends its block. The old gap-fill insert was off by one line and nested the new peer inside the next peer's markers.
- Gap detection compares whole numbers (`3` no longer matches `13`).
- Self-update only pulls from this repo, is syntax-checked before replacing the script, and is **off by default**.
- `nftables.service` is no longer enabled (Debian's `/etc/nftables.conf` runs `flush ruleset`, wiping iptables-nft, fail2ban and ipset rules).

**Networking**
- IP forwarding is set once in `/etc/sysctl.d/99-wireguard-manager.conf` instead of being turned off host-wide on `wg-quick down`. Uninstall removes that file again (runtime forwarding is left on until the next reboot so Docker or other tunnels aren't cut off).
- PostUp/PostDown add `FORWARD` accept rules (iptables/ip6tables) so clients work on hosts with a DROP forward policy (Docker, ufw). They use `-w 5` to wait for the xtables lock, so they don't fail when fail2ban or other scripts edit iptables at the same time during boot.
- Interface name overridable via `WIREGUARD_PUB_NIC`.
- Peer changes reload with `wg syncconf` instead of `wg addconf`.

**Tunnel and clients** (ideas from angristan/wireguard-install)
- Default tunnel subnets are `10.66.66.0/24` and `fd42:42:42::0/64` instead of all of `10.0.0.0/8`, so they don't collide with Docker, home/work LANs or other tunnels. Room for 253 peers; adding one more stops with a clear error instead of the old "roll over" logic that handed out addresses outside the subnet.
- Client configs use `Address = <ip>/32, <ip6>/128`. With the old `/8` a client lost access to any local network in the 10.x range.
- Client configs no longer force `MTU = 1280` (each device uses WireGuard's default; a commented line explains when to lower it). A custom peer MTU chosen at install is still written.
- Client configs no longer get a random `ListenPort`.
- The listen port is opened in iptables/ip6tables `INPUT` in PostUp and closed in PostDown, so a DROP input policy or geoblock rules don't silently block clients. Changing the port (option 13) stops the interface first so the old rule is removed, then starts it on the new port.
- After install the script checks the tunnel is actually up and tells you what to do if not (usually a reboot after a kernel update).
- New peers take the lowest free address from `.2` up and never reuse one in use (the last line of `wg0.conf` was taken as the highest address, which broke after a gap was filled).

**Server address**
- Public IP detection checks the server's own interfaces first (Nyr-style). One public address is used directly; several give you a menu; only private/CGNAT addresses mean the server is behind NAT, and then the address found online is offered as an editable default, where a hostname works too. Outside lookups are validated, so an empty or garbage reply is never used.
- The address you choose is actually used. Upstream ignored the custom/selected IP and always wrote the raw detection result into the endpoint.
- IPv6 detection skips ULA (`fd..`), temporary privacy and deprecated addresses.
- DDNS (`--ddns`) leaves hostname endpoints alone and keeps the current IP if it's still on the server.

**DNS**
- One DNS menu instead of two: public resolvers first (1 Cloudflare, default; 2 AdGuard; 3 NextDNS; 4 OpenDNS; 5 Google; 6 Verisign; 7 Quad9; 8 FDN; 9 Custom), then 10 Unbound on the server (optional content-blocker) and 11 Pi-Hole if installed. Upstream defaulted to Unbound, which takes over the host's `/etc/resolv.conf` and port 53.
- Headless installs default to Cloudflare. Set `DNS_PROVIDER_SETTINGS=10` for Unbound.
- Custom DNS (option 9) only accepts valid IPv4/IPv6 addresses, comma or space separated.

**Unbound**
- Root hints and blocklist download to a temp file with `curl --fail` and only replace the live file on success; a failed blocklist update is rolled back if `unbound-checkconf` fails, and Unbound is only restarted on a valid config.
- Root hints and blocklist no longer come from a random mirror (5 picks per run, including third-party CDNs like statically.io and combinatronics.io). Sources are tried in a fixed order with fallback: root hints use the distro copy (`/usr/share/dns/root.hints`, Debian/Ubuntu `dns-root-data`) first, then IANA's `internic.net`, then GitHub; the blocklist uses GitHub raw, then jsDelivr. Root hints must list the root servers to be accepted, and each file is downloaded once per update instead of twice.
- Own blocklist: set `CONTENT_BLOCKER_URL` (plain domain list or hosts format such as StevenBlack) and it's tried first. Entries are validated and de-duplicated.
- `cache-min-ttl` 86400 → 0 (records were cached for at least a day).
- `access-control: ::0` → `::/0`.

**Peers**
- Client configs are saved as `/etc/wireguard/clients/<peer>.conf` instead of `<peer>-wg0.conf`. Files from older versions are renamed automatically on the next run. A non-default interface (`WIREGUARD_PUB_NIC=wg1`) uses its own folder, `clients-wg1/`, so peer names can't collide.
- Default peer names are `peer1`, `peer2`, ... (next free number) instead of a random 50-character hex string.

**Fixes**
- `--help` exits instead of starting the installer.
- Requirement check uses `crontab` (no `cron` binary on Arch/Fedora) and drops the unused `ifup`; `PATH` includes `/usr/sbin` so nightly cron runs don't reinstall packages.
- Cron entries are de-duplicated on re-run.
- Port change edits only `ListenPort`, the metadata line and `Endpoint` (it used to replace the number anywhere, including keys) and restarts the interface.
- DDNS refuses to write an empty IP when detection fails.
- Backup includes `clients/`; backup and password file are root-only.
- Uninstall no longer leaves the restored `resolv.conf` immutable.
- Verify option no longer executes command output, and checks the right interface.
