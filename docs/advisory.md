# Advisory Summary

`linux-supply-chain-guard` is a read-only Linux host checker for supply-chain
incident response. It is meant for developer workstations, CI runners,
container build hosts, and multi-tenant Linux systems where untrusted package
payload execution could combine with local host weaknesses.

The initial posture checks cover AlmaLinux's May 13, 2026 Fragnesia /
`CVE-2026-46300` disclosure and known Linux persistence paths from public
Shai-Hulud / Here We Go Again reporting.

The June 2026 ITScape / `CVE-2026-46316` ARM64 KVM guest-to-host escape report
is now included as a posture lane for hypervisors and cloud-style ARM64 hosts.
The check does not run the PoC. It looks for ARM64 architecture evidence,
loaded KVM modules or KVM/ITS kernel configuration, and whether the running
kernel is below the upstream `6.15.0` fix baseline. Older distro kernels may be
fixed by vendor backports, so those findings require advisory confirmation
rather than a simple version-only verdict.

The May 20, 2026 OX Security DPRK npm RAT report is now included because it
targets developer workstations through npm package installation. This guard
checks dependency metadata for `terminal-logger-utils`, `pretty-logger-utils`,
`ts-logger-pack`, and `pinno-loggers`, plus behavior markers such as
`utils.cjs`, `/api/validate/keyboard-events`, `pwdKeyString`, and
`Telegram Desktop`. These checks are read-only and do not inspect secret file
contents.

The May 29, 2026 TeamPCP/Dynatrace watch pack is included as a weak-signal
exposure detector. It looks for Dynatrace token-shaped values, redacts those
values in output, and flags repo/service strings observed in public
threat-actor screenshots. These findings are correlation leads, not proof of
compromise: operators should compare them against repository visibility, CI
logs, package metadata, Dynatrace token inventory, and rotation status.

The June 5, 2026 PCPJack watch pack is included as host-residue detection for
the cloud SMTP relay network reported by Hunt.io and Security Affairs. The
report describes roughly 230 cloud servers used as authenticated outbound mail
relays through Chisel reverse tunnels, Sliver C2, relay verifier scripts, and
`xsync` persistence watching `/var/tmp/.xs`. These checks look for local
artifact paths and copied host metadata only; they do not scan the internet or
probe SMTP relays.

The June 2026 Hades / Miasma PyPI watch pack is included because Socket and
SecurityWeek reported fresh Mini Shai-Hulud-derived PyPI waves using executable
`*-setup.pth` startup hooks, Bun bootstrapping, `_index.js` payloads, `sys.path`
payload searching, and native `.abi3.so` import-time launchers. These checks
look for affected PyPI package versions, local runtime artifacts, suspicious
Python package layouts, and GitHub/CI exfiltration markers. They do not execute
Python, Bun, package managers, or cleanup actions.

Huntress' Heaven's Gate overview is included as weak-signal Windows evasion
context. The guard looks for analysis-note references to WOW64 mode-switching
or Heaven's Gate terms only when they co-occur with shellcode, injection, EDR
evasion, malware, or payload language plus stronger transition markers such as
far jump/call/return or selector `0x33` context. These findings are triage
leads and do not prove active compromise.

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

ITScape / `CVE-2026-46316` checks include:

- ARM64/aarch64 architecture evidence
- loaded `kvm`, `kvm_arm`, or `kvm_arm64` modules
- kernel config evidence for KVM and ARM GIC/vGIC ITS support
- upstream `6.15.0` baseline review for exposed ARM64 KVM hosts

Known supply-chain persistence checks include:

- `/tmp/transformers.pyz`
- `~/.config/systemd/user/gh-token-monitor.service`
- `~/.local/bin/gh-token-monitor.sh`
- `~/.config/gh-token-monitor/`
- `~/.config/systemd/user/pgsql-monitor.service`
- `/etc/systemd/system/pgsql-monitor.service`
- `~/.local/bin/pgmonitor.py`
- `/usr/bin/pgmonitor.py`

Known DPRK npm RAT dependency indicators include:

- `terminal-logger-utils`
- `pretty-logger-utils`
- `ts-logger-pack`
- `pinno-loggers`
- `utils.cjs`
- `/api/validate/keyboard-events`
- `pwdKeyString`
- `Telegram Desktop`

Newer Osj/@inf0stache reported DPRK/Famous Chollima-style loader behavior is
also covered when multiple execution signals co-occur:

- Socket.IO usage
- `/api/service` C2 fetch path
- `0001.dat` second-stage payload name
- local write and Node execution behavior

TeamPCP/Dynatrace weak-signal exposure indicators include:

- Dynatrace token-shaped values beginning with `dt0c01`, `dt0s01`, or related
  `dt0*` API/access-token prefixes
- `hard-copilot`
- `hard-csc`
- `hard-iam`
- `local-cluster-setup`
- `nonprod-dtappghrunner`
- `prod-copilot`
- `prod-csc`
- `prod-dtappghrunner`
- `prod-iam`
- `dynatrace.scorecards`
- `dynatrace.security.enrichment`
- `dynatrace.security.operations`
- `dynatrace.security.threats.exploits`
- `dynatrace.sensitive.data.center`
- `dynatrace.services`
- `dynatrace.snowflake.connector`
- `dynatrace.software.lifecycle`
- `dynatrace.specktrack`
- `dynatrace.storage.management`

PCPJack / cloud SMTP relay host-residue indicators include:

- `/var/tmp/.xs`
- `xsync`
- `/root/.sliver-client/configs/root_localhost.cfg`
- `/root/excalibur/smtp_proxies.csv`
- `chisel_verifier.py`
- `chisel_verified.json`
- `smtp.gmail.com:587`
- `38.242.204.245`
- `213.136.80.73`

Roundcube `CVE-2025-49113` webmail exposure checks include:

- versions before `1.5.10`
- `1.6.x` versions before `1.6.11`
- local PoC/exploit-runner artifacts mentioning `CVE-2025-49113`
- upload/session code-path review terms around
  `program/actions/settings/upload.php`, `_from`, and `rcube_session`

Argamal game-RAT residue checks include:

- `natives2_blob.bin`
- `zaesdl.dat`
- `asper1.freeddns.org`
- `Winst0.kozow.com`
- delayed `bitsadmin` second-stage fetch markers
- Windows Color System Calibration Loader COM-hijack persistence terms
- anti-analysis terms near loader behavior, including Sandboxie and Procmon64

Hades / Miasma PyPI indicators include:

- affected PyPI package versions reported by Socket, including MCP-themed and
  bioinformatics package clusters
- `*-setup.pth`
- `_index.js` inside Python package or virtualenv paths
- `.bun_ran`, `/tmp/b.zip`, `/tmp/b/bun`, and Bun download strings
- `sys.path` plus `_index.js` loader behavior
- `ensmallen_haswell.abi3.so`, `ensmallen_core2.abi3.so`, or `.abi3.so` paired
  with `_index.js`
- `Hades - The End for the Damned`
- `IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully`
- `Run Copilot`, `format-results`, and `results/results-*.json`

This project intentionally avoids exploit reproduction steps, cleanup
automation, and secret disclosure. It cannot prove a host is clean.
