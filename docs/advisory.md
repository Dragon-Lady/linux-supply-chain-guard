# Advisory Summary

`linux-supply-chain-guard` is a read-only Linux host checker for supply-chain
incident response. It is meant for developer workstations, CI runners,
container build hosts, and multi-tenant Linux systems where untrusted package
payload execution could combine with local host weaknesses.

The initial posture checks cover AlmaLinux's May 13, 2026 Fragnesia /
`CVE-2026-46300` disclosure and known Linux persistence paths from public
Shai-Hulud / Here We Go Again reporting.

This project also keeps advisory-only notes for urgent Linux exposure risks
that may affect build hosts, CI infrastructure, package mirrors, WSL developer
environments, or self-hosted developer services.

NGINX Rift / `CVE-2026-42945` is currently tracked in this advisory-only lane.
It affects NGINX Open Source and NGINX Plus versions `0.6.27` through `1.30.0`
via a heap buffer overflow in `ngx_http_rewrite_module`. Public reporting says
exploitation attempts have been observed in the wild. Worker-process crash is
exploitable; reliable RCE depends on a vulnerable rewrite configuration and
ASLR being disabled. This guard does not yet inspect NGINX versions or rewrite
configuration, so operators should patch exposed NGINX deployments through
vendor packages and verify configuration separately.

Sudo `CVE-2026-35535` is also tracked as advisory-only context. Sudo through
`1.9.17p2` before upstream commit `3e474c2` can mishandle failures while
dropping privileges before running the mailer. Vendor advisories describe this
as a local privilege-escalation path that may let a local attacker gain root
without sudoers membership. This is especially relevant to supply-chain response
hosts because a compromised package payload, CI job, or low-privilege shell can
turn local code execution into full host control. This guard does not yet
inspect installed sudo package versions, so operators should patch sudo through
distro packages and verify WSL/Linux hosts separately.

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
