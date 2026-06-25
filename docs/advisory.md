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

Delphos Labs' May 15, 2026 DirtyCBC / Linux RxGK writeup is included as a
kernel advisory and research-artifact provenance lane. The report describes
AF_RXRPC/YFS-RxGK RESPONSE decrypt-before-MAC page-cache poisoning through
`MSG_SPLICE_PAGES`, in-place `skb_to_sgvec()` / `crypto_krb5_decrypt()`
handling, and upstream mitigation work beginning with commit `aa54b1d27fe0`.
The guard flags copied advisory notes and local PoC markers only; it does not
run PoCs or claim exploitability from kernel version alone because vendor
backport status must be checked separately.

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

The June 2026 npm v12 readiness lane is included as pre-execution posture
guidance. GitHub, The Hacker News, and JFrog reporting all point to the same
shift: npm is moving high-risk install behavior from implicit trust to explicit
approval. Findings in this lane should be handled by narrowing `allowScripts`,
`allow-git`, and `allow-remote`, pinning reviewed versions, and re-reviewing on
upgrade. This does not prove a host is compromised and does not eliminate
runtime/import-time package risk.

JFrog's June 24, 2026 VS Code autorun / blockchain dead-drop report is included
because the malicious npm versions avoid normal lifecycle-script execution and
instead rely on trusted editor folder-open task behavior. The guard checks for
`html-to-gutenberg@4.2.11`, `fetch-page-assets@1.2.9`, folder-open tasks that
launch `public/fonts/fa-solid-400.woff2`, JFrog-reported C2/dead-drop strings,
runtime artifact terms, and Nextron's Go-package reuse lead as OSINT
correlation only. These checks do not fetch public PoCs or open third-party
repositories.

Huntress' Heaven's Gate overview is included as weak-signal Windows evasion
context. The guard looks for analysis-note references to WOW64 mode-switching
or Heaven's Gate terms only when they co-occur with shellcode, injection, EDR
evasion, malware, or payload language plus stronger transition markers such as
far jump/call/return or selector `0x33` context. These findings are triage
leads and do not prove active compromise.

Unit 42's PAN-OS GlobalProtect / `CVE-2026-0257` active exploitation brief is
included as a local log-hunting lane. The guard looks for reported source IPs,
reported client host ID/MAC/device-name values, and PoC client configuration
values in GlobalProtect or PAN-OS log metadata. Successful gateway-connected
events are prioritized because Unit 42 reported that only a small portion of
probed devices established VPN sessions.

Cyber Security News' Splunk Enterprise / `CVE-2026-20253` coverage is included
as a local posture and log-triage lane. The guard looks for Splunk Enterprise
10.x references, CISA KEV/BOD copied notes, PostgreSQL sidecar recovery
endpoints, and file-write/RCE-chain triage terms such as `.pgpass`,
`backupFile`, `pg_restore`, and `pg_dump`. Fixed-version information was not
available from the reachable source during intake, so version findings are
review prompts that should be checked against current Splunk vendor guidance.

SecurityWeek's June 18, 2026 REDCap exposure report is included as healthcare
web-application posture context. Censys reported about 8,500 internet-exposed
REDCap instances globally, only 1.18% on `17.1.3` as of June 16, 2026, and GTIG
reported UNC6508 targeting legacy REDCap servers for credential harvesting and
custom backdoor deployment including InfiniteRed. This guard flags REDCap
version references older than `17.1.3` as review prompts and flags copied
UNC6508/InfiniteRed triage notes. Operators should inventory exposure, patch
REDCap, avoid exposed legacy side-by-side versions, and keep REDCap databases
behind a firewall per vendor guidance.

CISA's June 18, 2026 Fortinet alert is included as edge-device hardening
context. The direct CISA page may be blocked by upstream access controls during
intake, but the alert title and contemporaneous reporting describe exposed
Fortinet/FortiGate firewall and VPN credentials, brute-force activity, VPN
authentication hashes, and Fortinet guidance that routine credential refresh and
MFA reduce risk. The guard flags local Fortinet/FortiGate/FortiOS/SSL VPN,
FortiCloud SSO, credential-dump, brute-force, and firewall configuration-export
triage notes so operators can inventory affected edge devices, rotate related
Fortinet/VPN/LDAP/AD credentials from a clean posture, restrict management-plane
exposure, enforce MFA, and review authentication/config-export logs.

The Hacker News' Operation Endgame / SocGholish report is tracked as WordPress
and DNS hygiene context, not as an indicator rule. The reachable report says
106 SocGholish-linked servers were disrupted and 14,971 infected WordPress sites
were cleaned, but it does not publish stable IOCs suitable for local matching.
Operators handling suspected SocGholish/FakeUpdates exposure should review
WordPress core/plugin/theme integrity, unauthorized CMS users, credential
rotation, webinject residue, and DNS/domain-shadowing changes.

BleepingComputer's June 24, 2026 Operation Endgame update expands the same
law-enforcement posture context to Amadey and StealC infrastructure. The report
describes 326 servers and 142 domains disrupted, about 27 million stolen
credentials recovered from over 385,000 compromised systems, and more than 200
malicious C2 domains/IPs identified in Microsoft's civil action. No stable
server list, domain list, hashes, or file paths were published in the reachable
article, so this remains source context rather than a local detector rule.

Proofpoint and IBM X-Force's June 24, 2026 StealC writeup adds technical
context for the same Operation Endgame disruption. It describes StealC as a
MaaS infostealer with Linux-based C2 panels, RC4-encrypted HTTP POST JSON C2
traffic, request types such as `create`, `upload_file`, `loader`, and `done`,
and optional loader delivery chains that can include other stealers, RATs,
miners, or ransomware. It also describes a now-patched C2 panel directory
traversal issue used in law-enforcement operations. Because the reachable
writeup does not publish stable C2 domains, IPs, hashes, or broadly useful host
file paths, the guard tracks it as advisory context rather than adding a local
detector rule.

The FBI IC3 June 18, 2026 PSA on malicious traffic distribution systems is
tracked in the same advisory lane. It describes compromised websites, poisoned
ads, phishing, and fake promotions redirecting users through TDS chains to
phishing pages, fake updates, malware, and financial scams. It recommends CMS
patching, strong/unique credentials, 2FA, WAF/security plugins, official plugin
and theme sources, and Windows endpoint monitoring for suspicious `wscript.exe`,
`cscript.exe`, and PowerShell web requests for `.js`, `.ps1`, or `.svg`
payloads. The PSA does not include stable IOCs, so no detector rule was added
for this intake.

Ars Technica's June 18, 2026 Microsoft Crypto Clipper report is included as a
mounted-host and Windows artifact triage lane. Microsoft described a
self-propagating USB worm that uses `.lnk` files, a portable Tor client,
SOCKS5 on `localhost:9050`, clipboard monitoring for wallet addresses or seed
phrases, screenshot capture, wallet-address replacement, Curl exfiltration, and
remote code execution. The guard checks for copied host metadata and incident
notes containing those terms; it does not inspect live clipboards, enumerate
USB devices, or execute Windows artifacts.

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

libssh2 `CVE-2026-55200` is tracked as a client-side SSH/SCP/SFTP exposure.
Public downstream tracker data describes an out-of-bounds write in
`ssh2_transport_read()` when the SSH `packet_length` field is not bounded, with
libssh2 through `1.11.1` affected and upstream commit `7acf3df` carrying the
packet-length boundary checks. Operators should patch distro packages, then
inventory statically linked or bundled clients such as curl, git, backup,
deployment, artifact fetch, mirror, SCP, and SFTP tooling that may not use the
system libssh2 package. The adjacent `CVE-2026-55199` ext-info DoS is included
as copied-advisory context because downstream packagers are triaging both
libssh2 fixes together.

The public `bikini/exploitarium` `libssh2-cve-2026-55200-poc` tree is tracked
only as a local PoC-artifact review signal. If those files appear on a
developer workstation, build host, or runner, confirm provenance and keep them
out of normal dependency, CI, and credential-bearing workflows unless they are
explicitly authorized research material.

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

DirtyCBC / Linux RxGK checks include:

- copied advisory terms such as `DirtyCBC`, `AF_RXRPC`, `YFS-RxGK`,
  `RxGK RESPONSE`, `MSG_SPLICE_PAGES`, and decrypt-before-MAC
- code-path markers such as `rxgk_decrypt_skb`, `skb_to_sgvec`, and
  `crypto_krb5_decrypt`
- upstream mitigation markers such as `aa54b1d27fe0`, `SKBFL_SHARED_FRAG`, and
  `skb_has_shared_frag`
- local public-PoC/provenance markers including `poc.c`, `poc.py`,
  `RXGK_SERVER_ENC_TOKEN`, `RXRPC_CHARGE_ACCEPT`, and
  `RXRPC_CLIENT_INITIATED`

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

Microsoft's June 18, 2026 AutoJack research is included as an agent-localhost
control-plane posture lane. AutoJack showed that a browsing agent rendering
untrusted web content on the same host as AutoGen Studio could cross a localhost
MCP WebSocket trust boundary and trigger host process execution when the local
control plane lacked authentication and executable allowlisting. The Hacker News
reported that `autogenstudio` pre-release builds `0.4.3.dev1` and `0.4.3.dev2`
contained the vulnerable MCP WebSocket handler, while the stable PyPI build
`0.4.2.2` did not include that route. This guard flags AutoGen Studio,
`/api/mcp/ws`, `StdioServerParams`, `server_params`, localhost port `8081`, and
the reported pre-release versions as review prompts. The broader lesson applies
to other agent frameworks: localhost is not a trust boundary when agents can
render untrusted pages and also reach privileged local services.

This project intentionally avoids exploit reproduction steps, cleanup
automation, and secret disclosure. It cannot prove a host is clean.
