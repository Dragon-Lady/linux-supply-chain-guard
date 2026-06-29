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
payload searching, and native `.abi3.so` import-time launchers. JFrog's June
25, 2026 companion analysis also adds host/CI seeding markers observed in the
Leo/RStreams and Backstage npm wave. These checks look for affected PyPI package
versions, local runtime artifacts, suspicious Python package layouts, and
GitHub/CI exfiltration or seeding markers. They do not execute Python, Bun,
package managers, or cleanup actions.

The June 2026 nf_tables / `CVE-2026-23111` lane is included as Linux
local-privilege-escalation posture and research-artifact triage. The guard
checks for affected public kernel trains, `nf_tables` module/config presence,
`kernel.unprivileged_userns_clone=1`, kernel.org fix markers, advisory terms
around `nft_map_catchall_activate()` and the inverted genmask check, and public
PoC/checker provenance markers. It does not clone, build, or run exploit code.

SentinelOne's June 2026 macOS.Gaslight analysis is included as mounted-root and
developer-workstation triage context. The guard checks copied host metadata and
analysis notes for the reported Gaslight SHA-256 values, the
`com.apple.system.services.activity` LaunchAgent label, Telegram Bot API
polling/exfiltration terms, standalone CPython staging through
`astral-sh/python-build-standalone`, Keychain/browser collection terms, and
LLM-triage prompt-injection bait. These checks do not execute Mach-O files,
Python, shell installers, or payload text.

THN and SOC Prime's June 2026 TonRAT Photo ZIP reporting is included as
mounted-root and copied-log triage for Windows hospitality-phishing evidence.
The guard looks for Booking Manager/Calendly and Google redirect lures,
`photo-*.zip` archives, image-looking `.png.lnk` shortcuts, PowerShell stagers,
user-space Node.js `v24.13.0` under `AppData\Local\Nodejs`, TON blockchain API
C2 discovery, encrypted WebSocket C2, and Run/RunOnce persistence terms. These
checks are lead generators for Windows/client incident notes and do not execute
shortcuts, scripts, or JavaScript implants.

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

Island's June 2026 BadBlocker / Adblock for YouTube analysis is included as
browser-extension inventory and source-review context. The guard flags the live
extension ID `cmedhionkhpnakcndndgjdbohmhepckk`, related removed extension IDs,
Adblock/Unistream infrastructure, and copied scriptlet terms such as
`scripletsRules`, `trusted-create-element`, `chrome.scripting.executeScript`,
MAIN-world execution, and weak full-URL `youtube.com` gate logic. Island and
The Hacker News described this as a dormant capability with no observed
malicious payload distribution, so findings are review leads rather than proof
of compromise.

Malwarebytes' June 2026 Chrome session-cookie theft report is tracked as a
Windows browser-profile and native-host review lane. The guard flags fake
`.pfd.js` PDF-lure attachments, Chrome policy force-install terms,
`NativeMessagingHosts` manifests, `chrome.runtime.sendNativeMessage`,
session-cookie theft, browser tab/URL/language/fingerprint collection, MFA
bypass/account-takeover language, and native-host PowerShell execution.

Confirmed matches should be treated as browser-session compromise, not just
password theft. Operators should preserve the Chrome profile, extension
directory, policy registry keys or JSON, native messaging manifests, temp-folder
drops, and PowerShell logs, then invalidate active web sessions for affected
accounts from a clean host.

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

Censys' June 24, 2026 Joomla SP Page Builder advisory is included as actively
exploited web-application posture context. `CVE-2026-48908` has a CVSS 10.0
rating and reportedly affects SP Page Builder versions `1.0.0` through `6.6.1`;
the issue can enable unauthenticated file upload and potential RCE, and is
patched in `6.6.2`. Censys reported 194,793 web properties loading the
component. The guard checks local Joomla/SP Page Builder metadata for affected
versions, copied Censys/exploit notes, and upload/RCE triage terms so operators
can patch, preserve evidence, and review uploaded files and web-server logs.

CISA's June 2026 KEV edge-device additions are included as urgent appliance
posture context. BleepingComputer reported active exploitation warnings for
Ubiquiti UniFi OS `CVE-2026-34908`, `CVE-2026-34909`, `CVE-2026-34910`, and
Lantronix EDS5000 `CVE-2025-67038`. Bishop Fox separately validated the UniFi
OS chain against UniFi OS Server `5.0.6` / `unifi-core 5.0.126`, with UniFi OS
Server `5.0.8` / `unifi-core 5.0.153` as the server fixed-version context. The
guard checks exported notes and mounted roots for affected-version metadata,
TCP `11443` management-interface exposure notes, auth-bypass/update-path triage
terms, `ucs-update` child-process language, and unexpected-sudo review terms.
Operators should patch, restrict management reachability, rotate secrets, and
treat exposed pre-patch UniFi OS consoles as possible root-level compromise.

CISA's June 25, 2026 KEV update for PTC Windchill and FlexPLM
`CVE-2026-12569` is included as an enterprise application RCE and webshell
triage lane. CISA lists PTC advisory `CS473270`, a June 28, 2026 due date, and
forensics-triage requirements under BOD `26-04`. The guard looks for copied KEV
notes, Windchill/FlexPLM deployment or log metadata, `X-windchill-req` request
header references, and JSP web shell path shapes such as
`/Windchill/login/<16 hex>.jsp`. Operators should apply PTC mitigations,
restrict external reachability, and preserve webroot/request/JVM evidence
before cleanup.

The June 2026 python.org release-management API disclosure is included as a
release-integrity and build-automation review lane. The report describes an
authentication-bypass issue that could have allowed forged admin-level API
requests and malicious release-file URL changes before the February 24, 2026
patch, with no reported exploitation. The guard flags copied incident notes,
Python release URL automation, non-official Python release-looking URLs, and
Sigstore/PGP/PEP 761 provenance terms so operators can verify mirrors, pinned
hashes, and signatures before trusting cached Python artifacts.

CPython `tarfile` / `CVE-2026-11940` is included as an archive-extraction code
review lane. The PSF advisory describes an incomplete fix for `CVE-2025-4330`
where `tarfile.extractall()` with the `data` or `tar` filter can be bypassed by
a crafted archive whose hardlink references a deeper symlink, causing the
fallback path to recreate the symlink at a shallower hardlink path and escape
the intended destination. The guard flags copied advisory terms, patch PR and
commit provenance, hardlink/symlink bypass mechanics, and Python code that uses
`tarfile.extractall()` or `extract()` with `filter="data"` or `filter="tar"` on
upload, artifact, cache, restore, import, or ingest paths. Findings are review
leads: verify PSF or vendor-fixed Python builds and avoid extracting untrusted
tar archives until patched.

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

Broadcom/Symantec's June 24, 2026 Backdoor.Mistic report is included as an
endpoint and ransomware-access-broker triage lane. Broadcom links the backdoor
to Woodgnat, also known as KongTuke, and the ModeloRAT toolkit, with reported
handoff relevance to Qilin, Interlock, Rhysida, Akira, 8Base, and Black Basta.
Zscaler's related MLTBackdoor analysis describes a malware family that provides
post-exploitation capabilities on demand. The guard flags copied advisory notes
and telemetry where Mistic/MLTBackdoor terms co-occur with ransomware-family,
remote-admin, Cobalt Strike/Impacket, process-injection, or command-execution
terms. Remote administration tools remain review signals only unless correlated
with unauthorized install, suspicious parent process, network, or credential
activity.

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

PackageKit `CVE-2026-41651` is tracked as a local privilege-escalation exposure
for hosts where unprivileged local users can call PackageKit over D-Bus.
Upstream advisory data marks PackageKit versions `1.0.2` through `1.3.4` as
affected and `1.3.5` as fixed. The guard flags installed Debian-family
`packagekit*` packages, then asks operators to verify distro backports rather
than relying on upstream-looking version strings alone.

Copied advisory and source notes are tracked when they mention PackageKit with
`InstallFiles`, `pk_transaction_set_state`, `transaction->cached_transaction_flags`,
TOCTOU/race-condition language, or `Pack2TheRoot`/GHSA provenance markers. These
signals are for defensive triage and provenance review only; the guard does not
attempt exploit reproduction.

Cloud bucket hijacking is tracked as a cloud storage posture review signal.
Unit 42 and follow-on reporting describe a same-name bucket recreation risk:
if an attacker can delete a bucket used as a destination for cloud logs,
replication, telemetry, or diagnostic exports, existing data-stream
configuration may continue writing to an attacker-controlled bucket with the
same globally unique name.

The guard flags copied notes mentioning Google Cloud Logging sinks, Pub/Sub
Cloud Storage destinations, Storage Transfer Service jobs, AWS S3 replication,
Amazon Data Firehose, and Azure Monitor diagnostic exports together with bucket
or storage-account deletion permissions. Mitigation notes such as VPC Service
Controls, AWS Service Control Policies, trusted organizational boundaries, and
account-regional S3 namespaces are tracked as configuration-review prompts.

MCP Python SDK `CVE-2026-52869` is tracked as an HTTP transport
principal-confusion issue in the PyPI `mcp` package. The guard flags dependency
metadata that names `mcp` versions before fixed release `1.27.2`, then looks
for SSE and stateful Streamable HTTP transport terms near bearer-token,
OAuth, authenticated-principal, or session-id configuration.

The exposure boundary matters: HTTP transports with authentication are the
review priority, specifically SSE and stateful Streamable HTTP. Stdio,
stateless Streamable HTTP, and no-auth deployments have different exposure.
Hosted or multi-tenant MCP client deployments should verify that token
verification populates a per-user `AccessToken.subject`; a shared OAuth
`client_id` alone can preserve cross-user session confusion.

Amazon Q Developer / AWS Language Servers `CVE-2026-12957` and
`CVE-2026-12958` are tracked as workspace trust-boundary issues. The guard
flags local Amazon Q plugin metadata below fixed baselines, copied AWS/Wiz
advisory terms, repository-local `.amazonq/mcp.json` files with `mcpServers`
that can execute `command`/`args`, and notes that place MCP execution near AWS
credential, API token, or SSH-agent inheritance.

The primary review priority is any untrusted workspace opened with an Amazon Q
Developer IDE plugin that bundles Language Servers for AWS before `1.69.0`.
Suspicious `.amazonq/mcp.json` entries containing shell, curl, PowerShell, or
`aws sts get-caller-identity` collection behavior should be treated as possible
developer credential exposure. Symlink notes are tracked separately for the
`CVE-2026-12958` path-outside-workspace trust-boundary issue.

Langflow `CVE-2026-33017` / `GHSA-vwmf-pq79-vjvx` is tracked as an
unauthenticated public-flow build RCE fixed in `1.9.0`. The vulnerable endpoint
is `POST /api/v1/build_public_tmp/{flow_id}/flow`; when attacker-controlled
`data` is accepted, arbitrary Python in node definitions can reach unsandboxed
`exec()` through flow-building code. The guard flags local Langflow versions
before `1.9.0`, endpoint/source terms, and campaign notes tied to the reported
cryptominer activity.

For the cryptominer campaign, do not scope response to cloud-spend abuse only.
The guard tracks `KORKERDS`, `init_rmount`, Kinsing/kill-list language,
XMRig/Monero/miner terms, and reused SSH-key or SSH-worm lateral-movement
notes. A confirmed hit should trigger credential and SSH key rotation plus
inspection of connected hosts for secondary persistence.

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

DirtyClone / `CVE-2026-43503` is tracked as a DirtyFrag-family page-cache
poisoning variant rather than as package malware. JFrog's June 25, 2026
analysis describes a Linux local privilege-escalation path through XFRM/IPsec
and skb cloning where `__pskb_copy_fclone` can fail to preserve
`SKBFL_SHARED_FRAG`. The Hacker News summary adds the related Copy Fail
`CVE-2026-31431`, `skb_shinfo()->flags` fix context, and multi-tenant
container/CI exposure framing. The guard flags copied advisory/provenance terms
such as `DirtyClone`, `Copy Fail`, `CVE-2026-43503`, `CVE-2026-31431`,
`nf_dup_ipv4`, `ip xfrm`, `TEE --gateway`, `CAP_NET_ADMIN`, `unshare -Urn`,
`kernel.unprivileged_userns_clone=0`, `48f6a5356a33`, and `v7.1-rc5`.
SecurityOnline's June 28, 2026 summary adds patch-provenance strings such as
`cef401de7be8c4e155c6746bfccf721a4fa5fab9`,
`fbeab9555564a1b98e8582cd106dfe46c4606991`, and the
`propagate shared-frag marker through frag-transfer helpers` impact phrase.
These are review leads: confirm vendor backport status, patch and reboot, and
do not compile or run PoC material on production or credential-bearing hosts.

Pedit COW / `CVE-2026-46331` is tracked in the same Linux kernel exposure
lane. Public reporting and distro trackers describe a local privilege
escalation path in the traffic-control `act_pedit` code path under
`net/sched/act_pedit.c`, with page-cache corruption impact and Dirty COW-style
copy-on-write implications. The guard flags copied advisory/provenance terms
such as `Pedit COW`, `CVE-2026-46331`, `tcf_pedit_act`, `tc pedit`,
`TCA_PEDIT_KEY_EX`, `skb_ensure_writable`, `skb_linearize`, `cls_u32`,
`CAP_NET_ADMIN`, `unprivileged user namespace`, and
`kernel.unprivileged_userns_clone=0`. These are review leads: verify distro
backport status, patch and reboot, review traffic-control module exposure, and
do not compile or run PoC material on production or credential-bearing hosts.

Known supply-chain persistence checks include:

- `/tmp/transformers.pyz`
- `~/.config/systemd/user/gh-token-monitor.service`
- `~/.local/bin/gh-token-monitor.sh`
- `~/.config/gh-token-monitor/`
- `~/.config/systemd/user/pgsql-monitor.service`
- `/etc/systemd/system/pgsql-monitor.service`
- `~/.local/bin/pgmonitor.py`
- `/usr/bin/pgmonitor.py`

The Trend Micro Deep Security Agent hook-reload lane tracks MatheuZ Security's
BMHook/TMHook reload-bypass analysis as local/mounted-root evidence review. The
guard flags copied logs and notes that combine Trend Micro Deep Security Agent
context with `bmhook`, `tmhook`, `dsa_filter`, `dsa_filter_hook`, `ds_am.init`,
agent-controlled module removal/reload behavior, livepatch unpatch/patch
transitions, `LKM DOWN`, and event-storm or telemetry-drop terms such as
`TELEMETRY_EVENT_DROPPED_COUNT`. These checks do not reproduce the event storm
or unload modules; they only surface possible monitoring-gap evidence.

The System Register Hijacking / `ret2entry` lane tracks kernel exploitation
research artifacts and copied notes, not active compromise. It flags references
to `swapgs Stack Pivoting`, `KERNEL_GSBASE_MSR`, `MSR_GSBASE`,
`entry_SYSCALL_64`, `entry_SYSCALL_compat`, `FineIBT`, `KERNEL_IBT`, `kCFI`,
`CR-Pinning`, `native_write_cr4`, `SPSR_EL1`, `ELR_EL1`, `VBAR_EL1`, and
KernelCTF-style exploit-porting context. Findings are provenance and mitigation
review leads only; do not build or run kernel modules, PoCs, or exploit
harnesses on normal workstations.

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
- `SEED_PAT` and `Seeder`

The ImmobiliareLabs npm lane tracks Socket's June 26, 2026 Miasma Mini
Shai-Hulud report covering republished `@immobiliarelabs` Backstage GitLab and
LDAP authentication packages. The guard flags the affected package/version
pairs, Phantom Gyp `binding.gyp` execution of root `index.js`, root loaders with
Bun `v1.3.13` and credential-theft terms, deployment-triggered GitHub Actions
release workflows, `codfish/semantic-release-action` leads, exfil repository
markers, and AI/IDE persistence paths such as `.github/setup.js`,
`.gemini/settings.json`, `.claude`, `.vscode/tasks.json`, and Cursor rules.

The Impacket `secretsdump` lane is a Windows/Active Directory artifact-review
check for local notes, scripts, reports, or command histories copied onto a
Linux workstation or mounted evidence tree. It flags `impacket-secretsdump` /
`secretsdump.py` references when paired with DCSync/DRSUAPI flags, VSS and WMI
or MMC execution modes, offline `SAM`/`SYSTEM`/`SECURITY`/`ntds.dit` hive
parsing, alternate auth material such as NTLM hashes, AES keys, Kerberos tickets,
and output artifacts such as `dump.ntds` or hash-table formats. Findings mean
the files should be treated as sensitive credential material or authorized
pentest/IR notes until provenance is confirmed.

The DAEMON Tools Lite lane covers Kaspersky and The Hacker News reporting on
compromised official Windows installers. It flags copied notes, command
histories, hashes, and mounted Windows trees that reference affected builds
`12.5.0.2421` through `12.5.0.2434`, the fixed `12.6.0.2445` remediation
target, tampered components such as `DTHelper.exe`,
`DiscSoftBusServiceLite.exe`, and `DTShellHlp.exe`, the
`env-check.daemontools[.]cc` / `38.180.107[.]76` C2 and download indicators,
payload names including `envchk.exe`, `cdg.exe`, `cdg.tmp`, `core.tmp`,
`mcrypto.chiper`, `mcrypto.dat`, and `crypto.dll`, published SHA-1 IOCs, the
PowerShell `DownloadFile` command shape, minimal-backdoor staging terms, and
follow-on QUIC RAT review terms. Findings are mounted-Windows or copied-note
triage leads; the guard does not execute Windows artifacts.

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

0DIN's June 2026 clean-repo research is included as an agent setup/error
recovery lane. The reported chain used normal-looking setup instructions,
`python3 -m axiom init`, a package first-run error that asked for that init
command, and a shell script that read attacker-controlled DNS TXT data with
`dig` before executing it through `bash -c`. The guard flags the demo-specific
`axiom` markers, package errors that instruct `python -m ... init`, and scripts
that execute DNS TXT output directly or through `base64 -d | bash`. Findings
mean "inspect before allowing automated recovery," not proof that a repo already
ran malware.

The June 2026 Gogs lane tracks self-hosted Git exposure-review context from a
FOFA `app="Gogs"` product query and a public Jorian Woltjer PoC reference. The
guard flags local deployment artifacts such as Gogs app config or repository
storage paths, copied FOFA/Gist references, and notes that combine Gogs with
path-traversal or Git-hook RCE triage language. Findings are inventory and
authorized-research provenance leads only: confirm patch level, public
registration policy, repository storage paths, custom Git hook settings, and
recent repository-create/push/admin activity from a clean posture.

The Exchange June 2026 lane covers Microsoft's SSRF/file-read advisories as
local/mounted-root inventory and log-hunting leads. `CVE-2026-45504` checks now
include Hawktrace's WOPI/EWS mechanics: EWS `ReferenceAttachment` and
`ProviderEndpointUrl`, `GetWopiTargetPropertiesByUrl`, attacker-controlled
`WebApplicationUrl` values, `FileWebRequest`, `GetWacAttachmentInfo`,
`GetWacUrl`, and fragment-obfuscated `file://...#` URLs that can drop appended
access-token parameters. These findings do not prove live Exchange patch state;
verify directly on the server and preserve EWS/IIS/WOPI evidence before
remediation.

This project intentionally avoids exploit reproduction steps, cleanup
automation, and secret disclosure. It cannot prove a host is clean.
