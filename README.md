# linux-supply-chain-guard

`linux-supply-chain-guard` is a read-only Linux host checker for developers and
incident responders reviewing supply-chain exposure on workstations, CI
runners, and build hosts.

It checks local host posture related to the May 2026 Linux supply-chain response
lane, including Fragnesia / `CVE-2026-46300` kernel exposure, ITScape /
`CVE-2026-46316` ARM64 KVM exposure, risky module
state, and known developer-tooling persistence paths reported in public
Shai-Hulud / Here We Go Again analysis. It also checks selected dependency
metadata for the OX-reported DPRK npm RAT package names that target developer
workstations through install-time payloads.

The May 29, 2026 TeamPCP/Dynatrace watch pack adds weak-signal exposure checks
for Dynatrace token-shaped credentials and repo/service names observed in
public threat-actor screenshots. These findings do not prove a Dynatrace breach
by themselves; they are meant to catch leaked strings in repos, dependency
metadata, logs, and mounted workspaces where malware-hash tooling may see
nothing.

The June 5, 2026 PCPJack watch pack adds host-residue checks for the exposed
cloud SMTP relay network reported by Hunt.io and Security Affairs. It looks for
Sliver/Chisel relay artifacts, `xsync` watchdog persistence, relay CSV/verifier
files, and high-signal IP/path strings. These checks are review signals for
mounted Linux hosts and cloud runners; they do not scan remote infrastructure.

The June 2026 Hades / Miasma PyPI watch pack adds local checks for affected
package versions, executable `*-setup.pth` startup hooks, Bun bootstrap and
`_index.js` loader behavior, `.abi3.so` native-extension launcher layouts, and
GitHub/CI exfiltration markers reported by Socket and SecurityWeek.

The June 2026 JFrog Solana FakeFix / CMS Windows loader watch pack adds checks
for malicious Solana-themed npm/PyPI package names, CMS-themed npm loader names,
Solana wallet/keypair paths, Telegram exfiltration, suspicious Solana RPC
redirection, Deno remote-loader execution, Windows Registry Run-key persistence,
mutex markers, and EXE-dropper filenames.

The June 2026 Socket GlassWASM / Open VSX watch pack adds checks for trojanized
Open VSX extension copies, suspicious WASM payload names, affected VSIX archive
names and hashes, TinyGo/WebAssembly host fingerprints, Solana memo dead-drop
markers, and Node child-process download/execute loaders.

The SafeDep Astro config-as-code watch pack adds local checkout checks for
suspicious `astro.config.*` loader behavior, blockchain/C2 relay markers,
horizontally hidden executable-looking payload lines, and `.gitignore` entries
that hide reported PR helper artifacts.

The June 2026 OpenClaw agent-safety watch pack adds local checkout checks for
OpenClaw versions before `2026.4.23` and risky OpenClaw configuration that
combines open inbound DMs, wildcard sender allowlists, or host/main/disabled
sandbox mode.

The June 2026 npm v12 readiness watch pack adds local checkout checks for old
npm pins, dependency install-script approval readiness, Git dependency sources,
remote tarball dependency sources, and broad repo `.npmrc` opt-ins. These are
local operator notifications only. JFrog's npm v12 analysis reinforces the same
lane: `allowScripts`, `allow-git`, and `allow-remote` approvals should stay
narrow, version-pinned, and re-reviewed on upgrade because attackers may target
already-approved packages or move payloads to runtime/import-time execution.

The June 2026 Oracle PeopleSoft watch pack adds local host and mounted-root
checks for CVE-2026-35273 posture and the UNC6240/ShinyHunters campaign
reported by Oracle and Google/Mandiant. It checks for affected PeopleTools
version references, PSEMHUB route evidence, PSEMHUB.war filesystem artifacts,
MeshCentral masquerade filenames, campaign network indicators, and extortion
markers. These are local operator notifications only.

The June 2026 Gentlemen ransomware watch pack adds local host and mounted-root
checks for Microsoft and Hunt.io reported artifacts: known hashes, ransom-note
and wallpaper filenames, mutex/service/task markers, PsExec self-propagation
markers, defense-evasion toolkit filenames, exposed operator toolkit scripts,
and reported network/session indicators. These are local operator notifications
only.

The June 2026 Operation Highland / Velvet Ant watch pack adds Sygnia-reported
Linux authentication-stack compromise checks for replaced PAM/OpenSSH
components, hidden credential-log paths, GS-Netcat staging, Nginx/FastCGI bridge
artifacts, process-masquerade strings, and the published SHA-1 IOC set. These
are local operator notifications only.

This project also tracks urgent Linux advisories as operator guidance when they
intersect supply-chain response hosts. NGINX Rift / `CVE-2026-42945` and Sudo
`CVE-2026-35535` are currently documented as advisory-only context; this guard
does not yet perform NGINX version, rewrite-module configuration, or distro sudo
package detection.

## Safety stance

- Read-only checks by default.
- No exploit testing.
- No malware execution.
- No automatic cleanup.
- No token revocation.
- No claim that a host is clean.
- Secret files are detected by path only; contents are not printed.
- Dynatrace token-shaped values are redacted in output.
- No telemetry, upload, or maintainer-side collection of scan results.

## Privacy

This guard does not provide a hosted service, send telemetry to the
maintainers, or upload scan results. It reads local host metadata and reports
findings to the terminal, or to a local report path only when the operator
explicitly provides `--report`.

Any output files are created in the operator's local environment unless the
operator separately chooses to share them.

Credential-adjacent files are reported by path only. The tool does not print
secret values, read private keys for content, or send results to the project
maintainers.

## Usage

```bash
npx linux-supply-chain-guard
```

Local checkout:

```bash
node bin/linux-supply-chain-guard.js
node bin/linux-supply-chain-guard.js / --json
node bin/linux-supply-chain-guard.js /mnt/recovered-root --report report.json --home /mnt/recovered-root/home/alice
```

Optional guarded dependency resolution for this checkout:

```bash
sfw npm install --package-lock-only --ignore-scripts --audit=false --fund=false
```

Socket Firewall is approved for guarded use in this repository as of
2026-05-21 after vendor confirmation of the `sfw-free` `v1.10.0` binary update
and local canary logs showing stable wrapper and binary hashes. Keep lifecycle
scripts suppressed on first contact and review any lockfile changes before
commit.

Socket's 2026-06-19 Launch Week Day 3 product note says Socket Firewall now
blocks malicious VS Code and Open VSX extensions before install or update. That
matches this guard's editor-extension watch lane: editor extensions execute in
developer environments with source, terminal, credential, and token access, so
pre-install blocking is a valid team safeguard rather than only a convenience
wrapper.

Exit codes:

- `0`: informational findings only
- `1`: warning or review findings
- `2`: critical findings
- `64`: command-line or runtime error

## Current checks

- AlmaLinux Fragnesia / `CVE-2026-46300` patched kernel posture:
  - AlmaLinux 8: `kernel-4.18.0-553.124.2.el8_10` and above
  - AlmaLinux 9: `kernel-5.14.0-611.54.4.el9_7` and above
  - AlmaLinux 10: `kernel-6.12.0-124.56.2.el10_1` and above
- Fragnesia-related module state for `esp4`, `esp6`, and `rxrpc`.
- Temporary module blacklist confirmation in `/etc/modprobe.d`.
- ITScape / `CVE-2026-46316` ARM64 KVM posture:
  - ARM64/aarch64 architecture detection from scanner options, `/proc/cpuinfo`,
    or kernel metadata
  - loaded `kvm`, `kvm_arm`, or `kvm_arm64` module exposure
  - kernel config signals for KVM and ARM GIC/vGIC ITS support
  - review finding when an exposed ARM64 KVM host is below upstream `6.15.0`
    and needs vendor backport confirmation
- Known Shai-Hulud / Here We Go Again persistence and payload paths:
  - `/tmp/transformers.pyz`
  - `gh-token-monitor.service`
  - `gh-token-monitor.sh`
  - `pgsql-monitor.service`
  - `pgmonitor.py`
- OX-reported DPRK npm RAT dependency indicators:
  - `terminal-logger-utils`
  - `pretty-logger-utils`
  - `ts-logger-pack`
  - `pinno-loggers`
  - `utils.cjs`
  - `/api/validate/keyboard-events`
- Osj/@inf0stache reported DPRK/Famous Chollima-style npm loader behavior:
  - Socket.IO usage paired with `/api/service`
  - `0001.dat` second-stage fetch/write/Node execution paths
- GitHub Advisory npm malware packages with all versions affected:
  - `atomic-lockfile`
  - `csc154-internall-depend`
  - `ecto-flag-read`
  - `@validate-sdk/v2`
  - `google-cloud-secret-manager-config-poc`
- AtomicArch / IronWorm AUR indicators:
  - AUR `PKGBUILD`, `.SRCINFO`, and `.install` metadata that references
    `atomic-lockfile`
  - AUR build/install scripts that invoke `npm` or `npx` while referencing
    `atomic-lockfile`
  - payload-behavior terms near `atomic-lockfile`, including eBPF/rootkit,
    `deps`, browser cookie, Vault, Docker/Podman, Slack, Discord, and Teams
    targeting language
- Panther OtterCookie npm indicators:
  - package names including `bjs-biginteger`, `bjs-lint-builder(s)`,
    `hjs-lint-builders`, `sjs-builder(s)`, and `npm-doc-builder`
  - Vercel-hosted C2 domains used for config retrieval and file upload
  - install-time `node test.js` / `postinstall` behavior markers
- OX / Socket easy-day-js / Mastra npm supply-chain indicators:
  - `easy-day-js`, `setup.cjs`, and `node setup.cjs --no-warnings`
  - reported C2 indicators including `23.254[.]164.92:8000` and
    `23.254[.]164.123:443`
  - stage-2/persistence indicators including `protocal.cjs`,
    `NodePackages`, `NvmProtocal`, `com.nvm.protocal`, `nvmconf.service`,
    `.pkg_history`, and `.pkg_logs`
- SafeDep procwire / routecraft Windows npm dropper indicators:
  - exact package names `procwire`, `routecraft`, `endpointmap`, `bytecraft`,
    and `staticlayer`
  - staged payload URL `files[.]catbox[.]moe/j4loim[.]chk`
  - `Microsoft-Delivery-Optimization/10.0`, `Zone.Identifier`,
    `[ZoneTransfer]`, `bitsadmin`, `curl.exe`, `windowsHide: true`, and
    updater-like executable names
- Hades / Miasma PyPI indicators:
  - affected package versions including `langchain-core-mcp`, `openai-mcp`,
    `instructor-mcp`, `tiktoken-mcp`, `ray-mcp-server`, and reported
    bioinformatics package versions
  - `*-setup.pth`, `_index.js`, `.bun_ran`, `oven-sh/bun/releases/download`,
    `subprocess.run`, and `sys.path` loader patterns
  - native `.abi3.so` extension layouts paired with `_index.js`
  - GitHub/CI markers including `Run Copilot`, `format-results`, and
    `Hades - The End for the Damned`
- Agentjacking / Sentry MCP indicators:
  - Sentry DSN or ingest surfaces wired into MCP/agent context
  - Sentry-style fake `## Resolution` content that asks an agent to run `npx`
    diagnostics before inspecting source
  - Tenet validation markers such as `X-Tenet-Security` and
    `ResponsibleDisclosure [SECURITY SCAN]`
- Roundcube `CVE-2025-49113` webmail exposure indicators:
  - installed Roundcube versions below `1.5.10` or `1.6.11`
  - local PoC/exploit-runner artifacts referencing `CVE-2025-49113`
  - upload/session code-path review terms such as
    `program/actions/settings/upload.php`, `_from`, and `rcube_session`
- Joomla JCE / `CVE-2026-48907` indicators:
  - JCE/JCE Pro versions below `2.9.99.6`
  - local CISA KEV / exploit notes referencing `CVE-2026-48907`
  - profile/upload triage terms matching the unauthenticated profile-creation
    and PHP upload/execution flaw
- Splunk Enterprise / `CVE-2026-20253` indicators:
  - Splunk Enterprise `10.x` references for vendor mitigation review
  - CISA KEV / BOD `26-04` copied notes for `CVE-2026-20253`
  - PostgreSQL sidecar recovery endpoints such as
    `/v1/postgres/recovery/backup` and `/v1/postgres/recovery/restore`
  - file-write/RCE-chain triage terms such as `.pgpass`, `pg_restore`,
    `pg_dump`, `backupFile`, and arbitrary file creation/truncation
- REDCap exposure posture indicators:
  - REDCap version references older than `17.1.3`, the latest version cited by
    Censys/SecurityWeek on 2026-06-16
  - legacy REDCap path/version strings such as `redcap_v16_0_17`
  - UNC6508 / InfiniteRed triage terms for clinical/medical research targets
  - reminders to inventory internet exposure, patch REDCap, avoid exposed
    legacy side-by-side versions, and keep the database behind a firewall
- SocGholish / FakeUpdates WordPress triage context:
  - Operation Endgame disrupted 106 SocGholish-linked servers and reported
    cleanup of 14,971 infected WordPress sites
  - FBI IC3 warns that malicious traffic distribution systems route users from
    compromised websites, poisoned ads, phishing, or fake promotions to
    phishing pages, fake updates, malware, or financial scams
  - no new stable domains, hashes, or file paths were published in the reachable
    report, so this remains advisory context rather than a detector rule
  - operators should review WordPress integrity, suspicious administrator
    accounts, CMS/plugin/theme patch state, credentials, and DNS/domain
    shadowing if SocGholish exposure is suspected
  - businesses should monitor suspicious `wscript.exe`, `cscript.exe`, and
    PowerShell web-request execution for delivered `.js`, `.ps1`, or `.svg`
    payloads where Windows endpoint telemetry is available
- Argamal game-RAT residue indicators:
  - `natives2_blob.bin` and `zaesdl.dat` artifact names
  - C2 domains `asper1.freeddns.org` and `Winst0.kozow.com`
  - delayed `bitsadmin` second-stage fetch markers
  - Windows Color System Calibration Loader COM-hijack persistence terms
- Microsoft/Ars Crypto Clipper USB worm indicators:
  - `Crypto Clipper`, `Trojan:Win32/CryptoBandits.A`, and Defender alert terms
  - USB `.lnk` propagation notes paired with Tor/SOCKS5, clipboard, seed phrase,
    or wallet-address replacement behavior
  - `localhost:9050`, portable Tor client, PowerShell screenshot capture, and
    Curl/web-request exfiltration triage terms
- Solana FakeFix / CMS Windows loader indicators:
  - Solana-themed npm names such as `@solana-labs/web3.js`,
    `solana-web3-stable`, `solana-rpc-client`, and `solana-mev-bot`
  - PyPI names `solana-cli-py`, `solana-web3`, `solana-web3-py`, and
    `spl-token-py`
  - CMS loader names `cms-storehub`, `cms-helpgit`, `cms-github`, `to-cms`,
    and `shopifyto-cms`
  - Solana keypair/wallet path strings, Telegram API exfil paths, Deno
    `run -A`, fake RPC `104.239.66.223:8899`, and Windows Run-key/persistence
    markers
- Socket GlassWASM / Open VSX indicators:
  - affected Open VSX extension references `vscode/exargd/vsblack@0.0.1` and
    `vscode/noellee-doc/flint-debug@0.1.1`
  - affected VSIX filenames `exargd.vsblack-0.0.1.vsix` and
    `noellee-doc.flint-debug-0.1.1.vsix`
  - suspicious WASM payload filenames `snqpkebiwrxmoivl.wasm` and
    `orybbbdsuqmaapel.wasm`
  - reported SHA-256 values, `dodod.lat`, Solana memo dead-drop wallet and
    program IDs, and loader code that combines WASM with `child_process`,
    `curl | bash`, PowerShell `irm | iex`, or `windowsHide`
- Aikido / BleepingComputer JetBrains Marketplace AI-key stealer indicators:
  - exact reported JetBrains plugin IDs such as `org.sm.yms.toolkit` and
    `com.dp.git.ai.tool`
  - reported exfiltration endpoint indicators including
    `39.107.60[.]51/api/software/key`
- Astro config-as-code supply-chain indicators:
  - `astro.config.*` files that reconstruct `require` and combine loader,
    eval/function, global mutation, or blockchain/C2 relay markers
  - network retrieval paired with eval/function execution behavior
  - long horizontally hidden executable-looking payload lines
  - `.gitignore` entries hiding `branch_structure.json`,
    `temp_auto_push.bat`, or `temp_interactive_push.bat`
- OpenClaw agent exposure indicators:
  - OpenClaw versions before `2026.4.23`
  - open inbound DM policy paired with wildcard `allowFrom`
  - open inbound DM policy paired with host/main/disabled sandbox mode
- npm v12 readiness indicators:
  - npm pins older than `11.16.0`
  - lockfiles with dependency install-script markers and no visible approval
    metadata
  - Git dependency sources and remote tarball dependency sources
  - broad `.npmrc` `allow-git`, `allow-remote`, or `allow-scripts` opt-ins
  - review reminder that approvals are temporary trust, not permanent package
    reputation
- Oracle PeopleSoft / CVE-2026-35273 indicators:
  - PeopleSoft PeopleTools `8.61` or `8.62` version references
  - PSEMHUB/PSIGW route references such as `/PSEMHUB/hub` and
    `/PSIGW/HttpListeningConnector`
  - JSP files and unexpected transaction/storage paths under `PSEMHUB.war`
  - MeshCentral masquerade filenames such as `meshagent64-azure-ops.exe`
  - ShinyHunters campaign network indicators including `azurenetfiles.net`
  - `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT`
- Palo Alto PAN-OS GlobalProtect / `CVE-2026-0257` log-hunting indicators:
  - Unit 42-reported source IP indicators in GlobalProtect logs
  - reported client host ID, MAC, and device-name values in successful
    gateway-connected events
  - PoC client configuration values: `endpoint_os_version` set to
    `Microsoft Windows 10 Pro 64-bit` and empty `source_user_info.domain`
- Gentlemen ransomware indicators:
  - known SHA-256 values for reported encryptor, PsExec, and wallpaper artifacts
  - `README-GENTLEMEN.txt`, `gentlemen.bmp`, and `gentlemen_system` markers
  - service/task strings including `UpdateSystem`, `UpdateUser`, `GupdateS`,
    and `GupdateU`
  - PsExec self-propagation flags including `--spread`, `--ip`, `--login`,
    and `--password`
  - exposed operator toolkit names including `dControl.exe`,
    `ConfigureDefender.exe`, `PCHunter64_new.exe`, `PowerTool64_new.exe`,
    `WinDefGpo_Reg.ps1`, `def1.bat`, `clearlog.bat`, `ngrok.exe`, and
    `rustdesk.exe`
  - reported network/session indicators including `176.120.22.127`
- Heaven's Gate / WOW64 evasion review indicators:
  - analysis-note terms such as `Wow64Transition`, `HeavensGate`, or
    `Heaven's Gate`
  - co-occurring 32-bit/64-bit process context plus shellcode, injection, EDR
    evasion, or malware language
  - stronger transition markers such as far jump/call/return or selector
    `0x33` context
- Operation Highland / Velvet Ant Linux auth-stack indicators:
  - Sygnia-published SHA-1 values checked against PAM/OpenSSH and high-signal
    campaign paths
  - hidden credential-log paths including `/usr/share/man9/ph/.ph.man` and
    `/usr/sbin/.ssh.log`
  - GS-Netcat and staging artifacts including `/usr/sbin/auditdb`,
    `/lib/systemd/system/chrom.service`, `gs.thc.org`, and `mobi.urgpt.dev`
  - Nginx/FastCGI bridge path `/usr/share/nginx/cgi/cgi-bin/uptime`
  - process-masquerade markers including `[khubd]`, `[kauditd] -sh`, and
    `smbd -D`
- TeamPCP/Dynatrace weak-signal exposure indicators:
  - Dynatrace token-shaped values such as `dt0c01.*` and `dt0s01.*`
  - `hard-copilot`, `hard-csc`, `hard-iam`, `local-cluster-setup`
  - `nonprod-dtappghrunner`, `prod-copilot`, `prod-csc`,
    `prod-dtappghrunner`, `prod-iam`
  - `dynatrace.scorecards`, `dynatrace.security.operations`,
    `dynatrace.snowflake.connector`, and related service-name strings
- PCPJack / cloud SMTP relay residue indicators:
  - `/var/tmp/.xs` Chisel relay payload path
  - `xsync` cron/systemd persistence markers
  - `/root/.sliver-client/configs/root_localhost.cfg`
  - `/root/excalibur/smtp_proxies.csv`
  - `chisel_verifier.py`, `chisel_verified.json`
  - `smtp.gmail.com:587`, `38.242.204.245`, and `213.136.80.73`
- Common developer credential surfaces by presence only.

## Advisory-only Watch Items

- NGINX Rift / `CVE-2026-42945`: heap buffer overflow in
  `ngx_http_rewrite_module`, reported against NGINX Open Source and NGINX Plus
  versions `0.6.27` through `1.30.0`. Public reporting says exploitation
  attempts are active in the wild. Worker-process crash is exploitable; possible
  RCE depends on vulnerable rewrite configuration and ASLR being disabled.
  Patch exposed NGINX deployments through vendor packages. This guard currently
  documents the risk but does not automatically inspect NGINX builds.
- Sudo `CVE-2026-35535`: local privilege escalation in sudo through `1.9.17p2`
  before upstream commit `3e474c2`, caused by non-fatal privilege-drop failures
  before running the mailer. A local attacker may be able to escalate to root
  without sudoers membership. Patch Linux workstations, CI runners, WSL
  environments, and build hosts through distro packages. This guard currently
  documents the risk but does not automatically inspect installed sudo packages.

## Interpreting results

Critical findings mean the host may need immediate containment or patching.
Warning and review findings mean the tool found posture or evidence that should
be checked by an operator. A clean run only means this version did not observe
the known indicators it checks.

## Sources

- AlmaLinux Fragnesia / CVE-2026-46300 disclosure:
  https://almalinux.org/blog/2026-05-13-fragnesia-cve-2026-46300/
- NVD CVE-2026-46300:
  https://nvd.nist.gov/vuln/detail/CVE-2026-46300
- Cyber Security News on ITScape / CVE-2026-46316 ARM64 KVM guest-to-host
  escape PoC:
  https://cybersecuritynews.com/poc-exploit-released-linux-kernel-vulnerability/
- JFrog Shai-Hulud: Here We Go Again:
  https://research.jfrog.com/post/shai-hulud-here-we-go-again/
- OX Security DPRK npm RAT writeup:
  https://www.ox.security/blog/north-korean-npm-infostealer-rat/
- Socket Hades PyPI wave analysis:
  https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave
- Socket newer Miasma/Hades PyPI wave analysis:
  https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious
- SecurityWeek Shai-Hulud Miasma/Hades summary:
  https://www.securityweek.com/over-100-npm-pypi-packages-hit-in-new-shai-hulud-supply-chain-attacks/
- BleepingComputer AtomicArch / AUR compromise summary:
  https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/
- Tenet Agentjacking Sentry/MCP writeup:
  https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/
- Cyber Security News Agentjacking summary:
  https://cybersecuritynews.com/agentjacking-attack-hijacks-ai-coding-agent/
- JFrog Solana FakeFix / CMS Windows loader report:
  https://research.jfrog.com/post/solana-fakefix/
- Socket GlassWASM Open VSX extension report:
  https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
- OX Security easy-day-js / Mastra npm supply-chain report:
  https://www.ox.security/blog/easy-day-js-supply-chain-attack-hits-mastra-ai-in-npm/
- Socket Mastra npm package compromise analysis:
  https://socket.dev/blog/mastra-npm-packages-compromised
- SafeDep procwire / routecraft Windows npm dropper campaign:
  https://safedep.io/procwire-npm-windows-dropper-campaign/
- BleepingComputer / Aikido JetBrains Marketplace AI-key stealer report:
  https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/
- GitHub Advisory for `google-cloud-secret-manager-config-poc`:
  https://github.com/advisories/GHSA-g6v5-9xpp-6hpx
- SupplyChainAttack incident for `ecto-flag-read`:
  https://supplychainattack.org/incident/malware-in-ecto-flag-read-m7p2-zqvzsn
- Panther OtterCookie npm campaign:
  https://panther.com/blog/tracking-an-ottercookie-infostealer-campaign-across-npm
- SafeDep Astro config blockchain C2 supply-chain report:
  https://safedep.io/astro-config-blockchain-c2-supply-chain/
- The Hacker News OpenClaw prompt-injection and agent-phishing report:
  https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html
- GitHub npm v12 breaking changes notice:
  https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/
- The Hacker News npm v12 install-script default change summary:
  https://thehackernews.com/2026/06/github-to-disable-npm-install-scripts.html
- JFrog npm v12 explicit trust analysis:
  https://jfrog.com/blog/npm-v12-from-implicit-to-explicit-trust/
- Oracle Security Alert Advisory for CVE-2026-35273:
  https://www.oracle.com/security-alerts/alert-cve-2026-35273.html
- Google Cloud / Mandiant PeopleSoft ShinyHunters campaign analysis:
  https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit
- Cyber Security News PeopleSoft CVE-2026-35273 exploitation summary:
  https://cybersecuritynews.com/oracle-peoplesoft-0-day-rce-vulnerability/
- The Hacker News Gentlemen ransomware victim-claim summary:
  https://thehackernews.com/2026/06/the-gentlemen-ransomware-claims-478.html
- Microsoft Threat Intelligence Gentlemen ransomware analysis:
  https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/
- Hunt.io Gentlemen ransomware exposed toolkit analysis:
  https://hunt.io/blog/ransomware-exposed-gentlemen-ransomware-toolkit-leaks-publicly
- Huntress Heaven's Gate defensive overview:
  https://www.huntress.com/cybersecurity-101/topic/what-is-heavens-gate
- Unit 42 PAN-OS CVE-2026-0257 active exploitation brief:
  https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/
- The Hacker News PAN-OS GlobalProtect CVE-2026-0257 summary:
  https://thehackernews.com/2026/06/palo-alto-warns-of-active-exploitation.html
- BleepingComputer / CISA Joomla JCE CVE-2026-48907 active exploitation:
  https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-joomla-plugin-flaw-by-friday/
- Cyber Security News Splunk Enterprise CVE-2026-20253 active exploitation:
  https://cybersecuritynews.com/splunk-enterprise-vulnerability-exploit/
- Cyber Security News / watchTowr Splunk Enterprise sidecar chain summary:
  https://cybersecuritynews.com/splunk-enterprise-pre-auth-rce-chain-exposes/
- SecurityWeek REDCap internet-exposure / UNC6508 report:
  https://www.securityweek.com/majority-of-internet-accessible-redcap-servers-outdated/
- The Hacker News Operation Endgame / SocGholish disruption report:
  https://thehackernews.com/2026/06/operation-endgame-disrupts-socgholish.html
- FBI IC3 PSA on malicious traffic distribution systems:
  https://www.ic3.gov/PSA/2026/PSA260618
- Ars Technica Microsoft Crypto Clipper USB worm report:
  https://arstechnica.com/security/2026/06/microsoft-spots-new-self-propagating-malware-for-stealing-cryptocurrency/
- The Hacker News on NGINX CVE-2026-42945 active exploitation:
  https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html
- The Register on NGINX Rift exploitation:
  https://www.theregister.com/security/2026/05/18/nginx-rift-attackers-waste-no-time-targeting-exposed-servers/
- Ubuntu CVE-2026-35535 tracker:
  https://ubuntu.com/security/CVE-2026-35535
- NVD CVE-2026-35535:
  https://nvd.nist.gov/vuln/detail/CVE-2026-35535
- Hunt.io PCPJack exposed relay network report:
  https://hunt.io/blog/pcpjack-230-cloud-servers-smtp-proxy-network-sliver-chisel
- Security Affairs PCPJack summary:
  https://securityaffairs.com/193189/cyber-crime/pcpjack-exposed-researchers-uncover-230-node-cloud-email-relay-network.html
- Sygnia Operation Highland / Velvet Ant report:
  https://www.sygnia.co/blog/operation-highland-velvet-ant/
- Sygnia Operation Highland / Velvet Ant IOC appendix:
  https://www.sygnia.co/wp-content/uploads/2026/06/Appendix_Indicators-of-Compromise.pdf
- The Hacker News Operation Highland / Velvet Ant summary:
  https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html
