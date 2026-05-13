# Advisory Summary

`linux-supply-chain-guard` is a read-only Linux host checker for supply-chain
incident response. It is meant for developer workstations, CI runners,
container build hosts, and multi-tenant Linux systems where untrusted package
payload execution could combine with local host weaknesses.

The initial posture checks cover AlmaLinux's May 13, 2026 Fragnesia /
`CVE-2026-46300` disclosure and known Linux persistence paths from public
Shai-Hulud / Here We Go Again reporting.

Fragnesia is a Linux kernel local-root flaw affecting supported AlmaLinux
releases through the `esp4`, `esp6`, and, on some AlmaLinux 9/10 systems,
`rxrpc` modules. This tool does not test exploitability. It checks kernel
release posture, loaded module state, and whether temporary module blacklist
mitigations are visible.

Known supply-chain persistence checks include:

- `/tmp/transformers.pyz`
- `~/.config/systemd/user/gh-token-monitor.service`
- `~/.local/bin/gh-token-monitor.sh`
- `~/.config/gh-token-monitor/`
- `~/.config/systemd/user/pgsql-monitor.service`
- `/etc/systemd/system/pgsql-monitor.service`
- `~/.local/bin/pgmonitor.py`
- `/usr/bin/pgmonitor.py`

This project intentionally avoids exploit reproduction steps, cleanup
automation, and secret disclosure. It cannot prove a host is clean.
