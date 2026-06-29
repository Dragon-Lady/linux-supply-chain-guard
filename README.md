# linux-supply-chain-guard

`linux-supply-chain-guard` is a read-only Linux host checker for developers and
incident responders reviewing supply-chain exposure on workstations, CI
runners, and build hosts.

It checks local host posture related to the May 2026 Linux supply-chain response
lane, including Fragnesia / `CVE-2026-46300` kernel exposure, ITScape /
`CVE-2026-46316` ARM64 KVM exposure, DirtyCBC/RxGK page-cache poisoning
research-artifact leads, risky module state, and known developer-tooling
persistence paths reported in public
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
GitHub/CI exfiltration and seeding markers reported by Socket, SecurityWeek,
and JFrog.

The June 2026 JFrog Solana FakeFix / CMS Windows loader watch pack adds checks
for malicious Solana-themed npm/PyPI package names, CMS-themed npm loader names,
Solana wallet/keypair paths, Telegram exfiltration, suspicious Solana RPC
redirection, Deno remote-loader execution, Windows Registry Run-key persistence,
mutex markers, and EXE-dropper filenames.

The June 2026 JFrog / The Hacker News PostCSS-lookalike Windows RAT watch pack
adds checks for the `postcss-minify-selector-parser`,
`postcss-minify-selector`, and `aes-decode-runner-pro` npm packages, plus
PowerShell/VBS/Python/Nuitka payload-stage markers and Chrome
credential/extension theft terms.

The June 2026 Socket GlassWASM / Open VSX watch pack adds checks for trojanized
Open VSX extension copies, suspicious WASM payload names, affected VSIX archive
names and hashes, TinyGo/WebAssembly host fingerprints, Solana memo dead-drop
markers, and Node child-process download/execute loaders.

The SafeDep Astro config-as-code watch pack adds local checkout checks for
suspicious `astro.config.*` loader behavior, blockchain/C2 relay markers,
horizontally hidden executable-looking payload lines, and `.gitignore` entries
that hide reported PR helper artifacts.

The June 2026 JFrog VS Code autorun / blockchain dead-drop watch pack adds
local checkout checks for hijacked `html-to-gutenberg@4.2.11` and
`fetch-page-assets@1.2.9` npm metadata, `.vscode/tasks.json` folder-open tasks
that launch the fake `fa-solid-400.woff2` payload path, JFrog-reported C2 and
blockchain dead-drop strings, reported fake-font SHA-256 hashes, and Nextron's
Go-package reuse lead as OSINT correlation only.

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
reported network/session indicators, and ESET-reported GentleKiller/BYOVD
EDR-killer suite markers. These are local operator notifications only.

The June 2026 Edgecution / Payouts King watch pack adds local host and
mounted-root checks for Zscaler-reported malicious Microsoft Edge extension
artifacts, Chrome native messaging host manifests, `native_host.bat`, Edge
`test1` and `Recovery` profile paths, headless `--load-extension` launch
commands, Outlook update lure terms, CloudFront websocket C2s, `AppKey`
registry setup strings, and published SHA-256 indicators. These are local
operator notifications only.

The June 2026 Island / The Hacker News Adblock for YouTube watch pack adds
local Chrome/Chromium/Edge extension inventory checks for
`cmedhionkhpnakcndndgjdbohmhepckk`, related removed Adblock extension IDs,
Adblock/Unistream infrastructure, and dormant server-controlled
`trusted-create-element` / MAIN-world scriptlet injection terms. These are
review signals, not proof that a malicious payload ran.

The June 2026 Operation Highland / Velvet Ant watch pack adds Sygnia-reported
Linux authentication-stack compromise checks for replaced PAM/OpenSSH
components, hidden credential-log paths, GS-Netcat staging, Nginx/FastCGI bridge
artifacts, process-masquerade strings, and the published SHA-1 IOC set. These
are local operator notifications only.

The June 2026 Squidbleed review lane adds Squid proxy posture checks for
installed Squid packages, Squid configuration files, and FTP proxy exposure via
`Safe_ports` port 21. It tracks `CVE-2026-47729`; because distribution
backports and Squid 7.6/7.7 fixed-version reporting have been inconsistent,
operator guidance still favors disabling FTP proxying unless it is explicitly
required.

The June 2026 NGINX critical exposure lane adds local checks for F5-reported
NGINX Open Source affected ranges for `CVE-2026-42530` and `CVE-2026-42055`,
HTTP/3/QUIC configuration, and the HTTP/2 proxy/gRPC configuration chain with
`ignore_invalid_headers off` and oversized `large_client_header_buffers`.

The June 2026 DifyTap watch pack adds local deployment checks for Dify versions
before `1.14.2`, Plugin Daemon/internal API exposure terms, file-preview and
chat-message file UUID routes, trace-provider exfiltration risk, and PDFium
document-parser review markers.

The June 2026 Langflow watch pack adds local deployment checks for Langflow
versions affected by `CVE-2026-10561`, `CVE-2026-7664`, and
`CVE-2026-55450`, PythonREPL/auto-login and webhook/MCP auth-bypass terms,
deprecated `/api/v1/upload/{flow_id}` route exposure, absolute upload
`file_path` leak artifacts, public-bind review, upload-size limit markers, and
the `LOGSPACE-LangFlow` FOFA/product fingerprint context.

The June 2026 Gogs exposure-review lane adds local/mounted-root checks for Gogs
deployment artifacts, `app="Gogs"` FOFA fingerprint notes, public PoC
provenance references, and path-traversal or Git-hook RCE triage terms. These
are review signals for exposed self-hosted Git services; the guard does not
include or run exploit steps.

The June 2026 Laravel Livewire watch pack adds local deployment checks for
`CVE-2025-54068` vulnerable `livewire/livewire` Composer versions before
`3.6.4`, broad v3 Composer constraints requiring lockfile verification, and
Imperva-reported shoc.enz credential-theft campaign indicators including
`xantibot[.]pw`, `.env` harvesting, `APP_KEY`/database credential extraction,
FTP `47.129.100.149`, Telegram, GoFile, and webhook.site exfiltration paths.

The June 2026 AryStinger watch pack adds router/NAS edge-device malware checks
for `/tmp/bin` `syswapd0`/Dropbear artifacts, port `2332` Dropbear persistence,
`ajb8`/`auq8`/`dataexplore`/`opi7` infrastructure, and legacy
D-Link/Linksys/QNAP CVE markers.

The June 23, 2026 CISA KEV edge-device watch pack adds local/mounted-root
triage checks for Lantronix EDS5000 `CVE-2025-67038` and Ubiquiti UniFi OS
`CVE-2026-34908`, `CVE-2026-34909`, and `CVE-2026-34910`, including BOD
`26-04`, vendor advisory, product-family, Bishop Fox unauthenticated RCE-chain
triage markers, exposed management-interface notes, and forensics-triage terms.

The June 2026 Cisco CUCM WebDialer watch pack adds local/mounted-root triage
checks for `CVE-2026-20230`, Cisco Unified Communications Manager / Unified CM
SME, WebDialer SSRF, file-write-to-root escalation terms, Cisco advisory
`cisco-sa-cucm-ssrf-cXPnHcW`, and OSINT-reported full-chain webshell/Tor
exploitation language.

The June 2026 Cisco Catalyst SD-WAN Manager watch pack adds local/mounted-root
triage checks for GTIG-reported exploitation involving `CVE-2026-20245`,
`CVE-2026-20127`, and `CVE-2026-20182`, rogue peer IP indicators,
`evil_tenant.csv`, `vconfd_script_upload_tenant_list.sh`, tenant-list upload
history, `troot` UID 0 artifacts, `vmanage-admin` default-account activity,
`/var/log/scripts.log`, `/var/log/auth.log`, and fixed-release references.

The June 2026 Microsoft Exchange watch pack adds local/mounted-root triage
checks for `CVE-2026-45502` EWS `InstallApp` / `ManifestUrl` SSRF,
`CVE-2026-45504` SSRF/file-read privilege-escalation language, Microsoft
Exchange Server build/update exports, June 2026 KB/build markers,
`PT-2026-47976`, public PoC artifact markers, and Hawktrace's WOPI/EWS
file-read chain terms including `GetWopiTargetPropertiesByUrl`,
`ReferenceAttachment`, `ProviderEndpointUrl`, `WebApplicationUrl`,
`FileWebRequest`, and fragment-obfuscated `file://...#` URLs.

The May 2026 Delphos DirtyCBC / Linux RxGK watch lane adds local/mounted-root
checks for copied advisory notes and research-artifact markers around
AF_RXRPC/YFS-RxGK RESPONSE decrypt-before-MAC page-cache poisoning,
`MSG_SPLICE_PAGES`, `rxgk_decrypt_skb`, `skb_to_sgvec`, upstream commit
`aa54b1d27fe0`, and public PoC context. This is a kernel posture and
authorized-research provenance lane; it does not test exploitability.

The June 2026 KnowBe4 Threat Labs ClickFix watch pack adds local host and
mounted-root checks for the `Review Past Due Doc.zip` / `.lnk` OneDrive lure,
clipboard-injected PowerShell, DNS TXT staging, `document-auth[.]icu`,
`italy-news[.]info`, `lootrioya[.]info`, and the reported ZIP/MSI/password
stealer SHA-256 values.

The June 2026 Nextron Research Packagist watch pack adds local/mounted-root
checks for malicious `dcat-auth-google-2fa@1.0.2.0`, `r[.]keepex[.]xyz`
credential exfiltration, the reported `979890` hardcoded 2FA bypass code, and
obfuscated PHP markers co-occurring with the package indicators.

The June 2026 macOS ClickFix watch pack adds local host and mounted-root checks
for fake-CAPTCHA Terminal paste commands that use `curl -fsSL`, `/tmp` DMG
downloads, `hdiutil attach -nobrowse`, automatic `.app`/`.pkg` launch,
Atomic macOS Stealer/AMOS terms, `s.01M0td.dmg`, `NNApp.app`,
`svs-verificationdate[.]beer`, and `196.251.107[.]171`.

The June 2026 macOS.Gaslight watch pack adds local host and mounted-root checks
for SentinelOne-reported Gaslight SHA-256 values, the
`com.apple.system.services.activity` LaunchAgent label, Telegram Bot API
polling/exfiltration terms, standalone CPython staging through
`astral-sh/python-build-standalone`, Keychain/browser collection terms, and
LLM-triage prompt-injection bait.

The June 2026 EvilTokens watch pack adds Microsoft OAuth device-code phishing
triage checks for browser-data/SOC exports, including AES-GCM browser-side
decryption notes, `/api/device/start`, `/api/device/gate/`,
`/api/device/status/`, `emp01825.workers.dev`, and the reported MD5. Shared
Cloudflare IPs from the analysis are intentionally not treated as stable IOCs.

The June 2026 BlueKit watch pack adds browser-in-the-middle phishing review
signals for Netcraft-reported `rrweb` DOM streaming over WebSocket, custom
CAPTCHA, WebRTC IP mismatch detection, browser fingerprint checks, top-level
CSS filter randomization, and phishing-infrastructure asset proxying. `rrweb`
alone is intentionally treated as context, not an IOC.

The June 2026 TonRAT Photo ZIP watch pack adds local/mounted-root triage checks
for hospitality phishing notes involving Booking Manager/Calendly and Google
redirect lures, `photo-*.zip` archives, image-looking `.png.lnk` shortcuts,
PowerShell stagers, user-space Node.js `v24.13.0` under `AppData\Local\Nodejs`,
TON blockchain API C2 discovery, encrypted WebSocket C2, and Run/RunOnce
persistence notes.

The June 2026 PixelSmash watch pack adds FFmpeg/libavcodec posture checks for
`CVE-2026-8461`, MagicYUV decoder exposure terms, older upstream-looking
FFmpeg versions before `8.1.2`, and high-risk media ingestion surfaces such as
Jellyfin, Nextcloud movie previews, PhotoPrism, Immich, OBS, and thumbnailers.

The June 2026 libssh2 client-exposure lane adds Debian-family package checks
and copied-advisory/source-note checks for `CVE-2026-55200`, the
`ssh2_transport_read()` packet-length out-of-bounds write fixed by upstream
commit `7acf3df`. It also tracks adjacent `CVE-2026-55199` notes because both
libssh2 fixes are being triaged together by downstream packagers. The lane also
flags local copies or notes from the public `bikini/exploitarium`
`libssh2-cve-2026-55200-poc` tree as PoC research artifacts.

The June 2026 PackageKit lane adds Debian-family package checks and
copied-advisory/source-note checks for `CVE-2026-41651`, a local privilege
escalation in PackageKit versions `1.0.2` through `1.3.4` fixed in `1.3.5`.
It flags `InstallFiles`, `pk_transaction_set_state`, and
`transaction->cached_transaction_flags` race-condition notes, plus
`Pack2TheRoot`/GHSA provenance markers as local research-artifact review leads.

The June 2026 cloud bucket hijacking lane adds copied-advisory and local note
checks for storage bucket deletion plus same-name recreation risks that can
reroute cloud data streams. It tracks Google Cloud Logging sinks, Pub/Sub
Cloud Storage destinations, Storage Transfer jobs, AWS S3 replication, Amazon
Data Firehose, and Azure Monitor diagnostic export context, along with bucket
delete permissions and perimeter mitigations such as VPC Service Controls,
Service Control Policies, and account-regional S3 namespaces.

The June 2026 MCP Python SDK lane adds PyPI `mcp` dependency checks for
`CVE-2026-52869` / `GHSA-jpw9-pfvf-9f58`, fixed in `1.27.2`. It flags affected
versions before `1.27.2`, SSE `session_id`/`SseServerTransport` exposure,
stateful Streamable HTTP `Mcp-Session-Id`/`StreamableHTTPSessionManager`
context, bearer-token/authenticated-principal terms, and hosted-client
`AccessToken.subject` isolation notes. Stdio, stateless Streamable HTTP, and
no-auth deployments are called out as different exposure cases.

The June 2026 Amazon Q Developer lane tracks AWS bulletin `2026-047-AWS`,
`CVE-2026-12957`, and `CVE-2026-12958` for Language Servers for AWS and
Amazon Q IDE plugins. It flags vulnerable-looking Amazon Q plugin metadata,
repository-local `.amazonq/mcp.json` command configs, MCP command/args entries
near cloud credential inheritance terms, suspicious `aws sts get-caller-identity`
collection behavior, and symlink trust-boundary review notes. Fixed baselines
are Language Servers for AWS `1.69.0`, Amazon Q Developer for VS Code `2.20`,
JetBrains `4.3`, Eclipse `2.7.4`, and AWS Toolkit with Amazon Q for Visual
Studio `1.94.0.0`.

The June 2026 ShapedPlugin Pro WordPress supply-chain watch pack adds local
WordPress tree checks for affected Pro plugin slugs and versions,
`LicenseLoader.php`, fake `woocommerce-subscription` /
`woocommerce-notification` plugin paths, `194.76.217[.]28:2871`,
`generate[.]2faplugin[.]org`, the REST backdoor endpoint, 2FA secret markers,
and the reported loader hash.

This project also tracks urgent Linux advisories as operator guidance when they
intersect supply-chain response hosts. NGINX Rift / `CVE-2026-42945` and Sudo
`CVE-2026-35535` are currently documented as advisory-only context; this guard
does not yet perform NGINX rewrite-module configuration or distro sudo package
detection for those separate advisories.

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
- DirtyFrag-family module state for `esp4`, `esp6`, and `rxrpc`.
- Temporary module blacklist confirmation in `/etc/modprobe.d`.
- Trend Micro Deep Security Agent hook reload bypass indicators:
  - `bmhook`, `tmhook`, `dsa_filter`, `dsa_filter_hook`, `ds_am.init`,
    `/opt/ds_agent`, and `ds_agent.service` metadata
  - copied logs showing agent-controlled `rmmod` / module reload behavior,
    livepatch unpatch/patch transitions, `LKM DOWN`, or reload breadcrumbs
  - event-storm and telemetry-gap terms such as
    `TELEMETRY_EVENT_DROPPED_COUNT`, `event.dropped`,
    `bmhook_throttle_check`, `bmhook_scan_enqueue`, `tmbpf_send_event`,
    `enable_loop_prevention`, `thresholdBLP`, and `enableBLP`
- System Register Hijacking / `ret2entry` research indicators:
  - `System Register Hijacking`, `ret2entry`, `swapgs Stack Pivoting`,
    `KERNEL_GSBASE_MSR`, `MSR_GSBASE`, `entry_SYSCALL_64`,
    `entry_SYSCALL_compat`, `FineIBT`, `KERNEL_IBT`, and `kCFI`
  - adjacent register-technique terms including `native_write_cr4`,
    `native_write_cr0`, `CR-Pinning`, `wrgsbase`, `wrfsbase`, `MSR_FSBASE`,
    `SPSR_EL1`, `ELR_EL1`, `VBAR_EL1`, and `PAN MSR`
  - PoC/provenance terms such as `KernelCTF`, vulnerable kernel module notes,
    and exploit-porting references; these are research leads only
- ITScape / `CVE-2026-46316` ARM64 KVM posture:
  - ARM64/aarch64 architecture detection from scanner options, `/proc/cpuinfo`,
    or kernel metadata
  - loaded `kvm`, `kvm_arm`, or `kvm_arm64` module exposure
  - kernel config signals for KVM and ARM GIC/vGIC ITS support
  - review finding when an exposed ARM64 KVM host is below upstream `6.15.0`
    and needs vendor backport confirmation
- DirtyCBC / Linux RxGK review indicators:
  - `DirtyCBC`, `AF_RXRPC`, `YFS-RxGK`, `RxGK RESPONSE`, and
    `MSG_SPLICE_PAGES` advisory terms
  - decrypt-before-MAC/page-cache poisoning terms near `rxgk_decrypt_skb`,
    `skb_to_sgvec`, or `crypto_krb5_decrypt`
  - upstream fix marker `aa54b1d27fe0`, `SKBFL_SHARED_FRAG`, and
    `skb_has_shared_frag`
  - public PoC/provenance markers such as `poc.c`, `poc.py`,
    `RXGK_SERVER_ENC_TOKEN`, `RXRPC_CHARGE_ACCEPT`, and
    `RXRPC_CLIENT_INITIATED`
- DirtyClone / `CVE-2026-43503` review indicators:
  - `DirtyClone`, `Copy Fail`, `DirtyFrag`, `CVE-2026-43503`,
    `CVE-2026-31431`, `CVE-2026-43284`, `CVE-2026-43500`, and
    `CVE-2026-46300` advisory terms
  - clone-path markers such as `__pskb_copy_fclone`, `nf_dup_ipv4`,
    `skb_shinfo`, `skb_shift`, `skb_segment`, `skb_gro_receive`, and
    `tcp_clone_payload`
  - XFRM/IPsec, `CAP_NET_ADMIN`, `unshare -Urn`, `ip xfrm`, `TEE --gateway`,
    `esp_input()`, and `kernel.unprivileged_userns_clone=0` terms
  - upstream fix/release markers including `48f6a5356a33`, `9e171fc1d7d7`,
    `v7.1-rc5`, and `SKBFL_SHARED_FRAG`
- Pedit COW / `CVE-2026-46331` review indicators:
  - `Pedit COW`, `CVE-2026-46331`, `act_pedit`, and
    `net/sched/act_pedit.c` advisory terms
  - traffic-control mutation path terms such as `tcf_pedit_act`, `tc pedit`,
    `TCA_PEDIT_KEY_EX`, `pedit ex`, `skb_ensure_writable`, and
    `skb_linearize`
  - exposure/mitigation terms including `cls_u32`, `CAP_NET_ADMIN`,
    `unprivileged user namespace`, and `kernel.unprivileged_userns_clone=0`
  - copied PoC/provenance markers such as `tc qdisc`, `tc filter`,
    `tc action`, and `unshare -Urn` are review-only signals
- nf_tables / `CVE-2026-23111` review indicators:
  - affected upstream kernel trains from the public checker notes, including
    `6.18 < 6.18.10`, `6.12 < 6.12.70`, `6.6 < 6.6.124`,
    `6.1.36 < 6.1.163`, and `5.15.121 < 5.15.200`
  - `nf_tables` module/config presence paired with
    `kernel.unprivileged_userns_clone=1`
  - `nft_map_catchall_activate`, `nft_set_elem_active`,
    `nft_setelem_data_activate`, `nft_data_hold`, `NFT_GOTO`, `DELSET`,
    `DELCHAIN`, `pipapo`, `catchall element`, and `chain->use` advisory terms
  - kernel fix markers including `8c760ba4e36c750379d13569f23f5a6e185333f5`
    and upstream `f41c5d151078c5348271ffaf8e7410d96f2d82f8`
  - public PoC/provenance markers such as
    `Baba01hacker666/CVE-2026-23111`, `CVE-2026-23111-checker.py`,
    `exploit_full.c`, and `exploit_full.b64` are review-only signals
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
  - `signup-embedder`
  - `ts-grok`
- Checkmarx ChainVeil / SuccessKey npm indicators:
  - typosquat package names including `tailwindcss-merge`, `sass-format`,
    `sass-formats`, `tailwindcss-animates-kit`, `tailwindcss-animatics`,
    `clsx-tailwind`, `typeorm-encrypt`, `rate-limits-flexible`, and
    `rate-limit-flexible`
  - import-time loader markers in `lib/lib.min.js`, `global['_V']='A6-*'`,
    `successkeyteck`, XOR-key fragments, and seeded shuffler context
  - C2 IPs `166.88.54.158`, `198.105.127.210`, and `23.27.202.27`, plus
    `/$/boot`, `/upload`, WebSocket C2, Tron/Aptos/BSC C2 strings, and
    long-space-padded shell-config persistence markers
- Supply Chain Attack catalog npm malware indicators:
  - `free-claude`
  - `free-anthropic-claude`
  - June 23 package-cluster names such as `search-from-search`,
    `node-fetch-utils`, `signup-embedder`, `node-core-libs`, `calculate-helper`,
    `cursorai-agent`, and `vitest-cli`
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
  - JFrog-reported seeding markers including `SEED_PAT` and `Seeder`
- Agentjacking / Sentry MCP indicators:
  - Sentry DSN or ingest surfaces wired into MCP/agent context
  - Sentry-style fake `## Resolution` content that asks an agent to run `npx`
    diagnostics before inspecting source
  - Tenet validation markers such as `X-Tenet-Security` and
    `ResponsibleDisclosure [SECURITY SCAN]`
- AutoJack / local agent-control-plane indicators:
  - AutoGen Studio / `autogenstudio` references near local MCP WebSocket routes,
    `StdioServerParams`, `server_params`, or localhost port `8081`
  - reported `autogenstudio` pre-release builds `0.4.3.dev1` and `0.4.3.dev2`
  - reminders that localhost is not a trust boundary when a browsing agent can
    render untrusted web content on the same host
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
- Joomla SP Page Builder / `CVE-2026-48908` indicators:
  - SP Page Builder versions `1.0.0` through `6.6.1`
  - local Censys/exploit notes referencing `CVE-2026-48908`, active
    exploitation, unauthenticated file upload, or potential RCE
  - upload/RCE triage terms around `com_sppagebuilder` and SP Page Builder
- Splunk Enterprise / `CVE-2026-20253` indicators:
  - Splunk Enterprise `10.x` references for vendor mitigation review
  - CISA KEV / BOD `26-04` copied notes for `CVE-2026-20253`
  - PostgreSQL sidecar recovery endpoints such as
    `/v1/postgres/recovery/backup` and `/v1/postgres/recovery/restore`
  - file-write/RCE-chain triage terms such as `.pgpass`, `pg_restore`,
    `pg_dump`, `backupFile`, and arbitrary file creation/truncation
- CISA KEV June 23, 2026 edge-device indicators:
  - Lantronix EDS5000 / EDS5008 / EDS5016 / EDS5032 references paired with
    `CVE-2025-67038`, code injection, `username` parameter, or root-privilege
    language
  - Ubiquiti UniFi OS references paired with `CVE-2026-34908`,
    `CVE-2026-34909`, `CVE-2026-34910`, Security Advisory Bulletin 064,
    command injection, path traversal, or improper access control language
  - UniFi OS Server `5.0.6` / `unifi-core 5.0.126` vulnerable-version
    metadata and `5.0.8` / `unifi-core 5.0.153` fixed-version context
  - management-interface exposure terms including TCP `11443`, `0.0.0.0:11443`,
    admin interface, and web interface notes
  - Bishop Fox triage markers including `/api/auth/validate-sso/`,
    `ucs/update/latest_package`, `package-update`, `ucs-update`, child-process,
    and unexpected-sudo review terms
  - CISA KEV, BOD `26-04`, and forensics-triage notes for exported appliance
    inventories or incident-response files
- PTC Windchill/FlexPLM / `CVE-2026-12569` indicators:
  - CISA KEV catalog version `2026.06.25`, PTC advisory `CS473270`, and
    `CVE-2026-12569` copied notes
  - Windchill/FlexPLM references paired with improper input validation,
    unauthenticated remote code execution, `CWE-20`, `CWE-502`, or BOD `26-04`
  - JSP web shell triage terms, including `/Windchill/login/<16 hex>.jsp`
  - `X-windchill-req` request-header review terms for access-log hunting
- python.org release-management API trust indicators:
  - copied notes about forged admin-level API requests, release-file metadata,
    authentication bypass, or malicious Python release download URLs
  - official host context such as `www.python.org/ftp/python`,
    `www.python.org/downloads/release`, and `downloads.nyc1.psf.io`
  - release provenance terms such as `Sigstore`, `PGP signature`, `PEP 761`,
    and `Trail of Bits`
  - Python release-looking download URLs outside official python.org/PSF hosts
    are warning-level mirror/provenance review leads
- Cisco CUCM WebDialer / `CVE-2026-20230` indicators:
  - Cisco Unified Communications Manager / Unified CM / Unified CM SME
    references paired with WebDialer, SSRF, or Cisco advisory
    `cisco-sa-cucm-ssrf-cXPnHcW`
  - file-write and root-escalation language from the Cisco/NVD record
  - OSINT escalation terms for full-chain exploitation, webshell drops, Tor, or
    automated sweeps
- Cisco Catalyst SD-WAN Manager zero-day log-hunting indicators:
  - `CVE-2026-20245`, `CVE-2026-20127`, and `CVE-2026-20182`
  - Rogue peer IP indicators from GTIG reporting
  - `evil_tenant.csv`, `vconfd_script_upload_tenant_list.sh`, and
    `request tenant-upload tenant-list`
  - `troot`, `/etc/passwd`, `/etc/shadow`, `/var/log/scripts.log`, and
    `/var/log/auth.log`
  - Fixed-release references including `20.9.9.2`, `20.12.7.2`, `20.15.4.5`,
    `20.15.5.3`, `20.18.3.1`, and `26.1.1.2`
- REDCap exposure posture indicators:
  - REDCap version references older than `17.1.3`, the latest version cited by
    Censys/SecurityWeek on 2026-06-16
  - legacy REDCap path/version strings such as `redcap_v16_0_17`
  - UNC6508 / InfiniteRed triage terms for clinical/medical research targets
  - reminders to inventory internet exposure, patch REDCap, avoid exposed
    legacy side-by-side versions, and keep the database behind a firewall
- Fortinet / FortiGate credential-exposure posture indicators:
  - local CISA or incident notes for the June 18, 2026 Fortinet device hardening
    alert
  - FortiGate/FortiOS/SSL VPN/FortiCloud SSO terms, `FortiBleed`, credential
    dump/brute-force language, VPN authentication hashes, and firewall
    configuration export terms
  - FortigateSniffer/FortiBleed tooling markers including `fg_sniffer`,
    `mpbrute2.bin`, `forticheck`, `SNIFTRAN`, `PCAP Deep Analysis Toolkit`,
    `diagnose sniffer packet`, `harvestresults`, and reported campaign IPs
  - reminders to inventory Fortinet edge devices, rotate Fortinet/VPN/LDAP/AD
    credentials from a clean posture, enforce MFA, restrict management-plane
    exposure, and review authentication/config-export logs
- SocGholish / FakeUpdates WordPress triage context:
  - Operation Endgame disrupted 106 SocGholish-linked servers and reported
    cleanup of 14,971 infected WordPress sites
  - the June 24, 2026 BleepingComputer update reports a related Operation
    Endgame action against Amadey and StealC infrastructure: 326 servers and
    142 domains disrupted, about 27 million stolen credentials recovered from
    over 385,000 compromised systems, and more than 200 malicious C2 domains/IPs
    identified in Microsoft's civil action
  - Proofpoint and IBM X-Force's June 24, 2026 StealC writeup adds technical
    context on StealC C2 panels, RC4-encrypted HTTP POST JSON request types,
    optional loader payload delivery, and the law-enforcement disruption
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
- KnowBe4 Threat Labs ClickFix phishing indicators:
  - `Review Past Due Doc.zip` / `.lnk` OneDrive lure terms
  - Win+R / clipboard-injected PowerShell / DNS TXT staging language
  - infrastructure domains `document-auth[.]icu`, `italy-news[.]info`, and
    `lootrioya[.]info`
  - reported ZIP, MSI/RMM, and password-stealer SHA-256 values
- macOS ClickFix AMOS DMG indicators:
  - `curl -fsSL` into `/tmp`, `hdiutil attach -nobrowse`, and automatic
    `.app`/`.pkg` launch command-chain language
  - `s.01M0td.dmg`, `NNApp.app`, Atomic macOS Stealer/AMOS, Keychain prompt,
    Ledger Live, and Trezor Suite replacement terms
  - infrastructure `svs-verificationdate[.]beer` and `196.251.107[.]171`
- macOS.Gaslight indicators:
  - SentinelOne-reported Mach-O, sibling BONZAI, Python payload, and bash
    installer SHA-256 values
  - Apple XProtect labels `MACOS_BONZAI_COBUCH` and `AIRPIPE`
  - `com.apple.system.services.activity` LaunchAgent label and
    `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`
  - Telegram Bot API `getUpdates`, `attach://`, `tg_room_id`, and error-code
    terms; `temp/collected_data.zip`; `login.keychain-db`
  - `cpython-3.10.18`, `PY_VERSION=3.10.18`, `BUILD_DATE=20250708`, and
    `astral-sh/python-build-standalone`
  - LLM-triage prompt-injection bait terms such as `38 fabricated`,
    `LLM-assisted triage`, `token expiry`, `out-of-memory`, `disk exhaustion`,
    and `static-analysis flags`
- EvilTokens Microsoft OAuth device-code phishing indicators:
  - `EvilTokens`, `oauth-ms-phish`, and `Microsoft OAuth device-code phishing`
    triage terms
  - browser-side `AES-GCM` / decrypted DOM visibility-gap language
  - `/api/device/start`, `/api/device/gate/`, `/api/device/status/`,
    `emp01825.workers.dev`, and MD5 `fcd1b654a0b3e8f85ca7cfdafe494d4b`
  - device-code flow co-occurrence checks for `userCode`, `sessionId`, and
    verification URI handling
- BlueKit browser-in-the-middle phishing indicators:
  - `Bluekit`, `Browser-in-the-Middle`, `BitM`, and `rrweb` near login-page
    DOM streaming or WebSocket terms
  - custom CAPTCHA, WebRTC IP mismatch detection, browser fingerprint checks,
    headless-browser checks, and top-level CSS filter randomization
  - asset proxying language for images, fonts, and CSS fetched through
    phishing infrastructure
- TonRAT Photo ZIP phishing indicators:
  - hospitality lure context such as Booking Manager, Calendly, hotel-industry,
    or reservation-photo language paired with Google redirect/share links,
    Cloudflare Turnstile, or `.cfd` staging domains
  - attachment names such as `photo-<digits>.zip` and image-looking shortcut
    names such as `IMG-*.png.lnk` or `PHOTO-*.png.lnk`
  - PowerShell/LNK stager terms paired with user-space Node.js `v24.13.0`,
    `AppData\Local\Nodejs`, or `node-v24.13.0`
  - TonRAT, TON blockchain API / `tonapi.io`, encrypted WebSocket C2, and
    Run/RunOnce persistence review terms
- Mistic / MLTBackdoor ransomware access-broker indicators:
  - `Backdoor.Mistic`, `Mistic RAT`, `MLTBackdoor`, `Woodgnat`, `KongTuke`,
    and `ModeloRAT` advisory or telemetry terms
  - co-occurrence with ransomware-family handoff terms including `Qilin`,
    `Interlock`, `Rhysida`, `Akira`, `8Base`, and `Black Basta`
  - nearby post-exploitation and remote-admin tooling terms such as
    `Cobalt Strike`, `Impacket`, `AnyDesk`, `Splashtop`, and `ScreenConnect`
  - process-injection and command-execution triage language such as
    `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `cmd.exe`,
    `powershell.exe`, and `schtasks`
- FFmpeg PixelSmash indicators:
  - installed `ffmpeg` / `libavcodec*` Debian-family packages
  - upstream-looking versions before FFmpeg `8.1.2` flagged for vendor-backport
    review
  - `PixelSmash`, `CVE-2026-8461`, `MagicYUV`, `magicyuv`, `ffprobe`, and
    `VFS..D magicyuv` triage terms
  - media-ingestion surfaces including Jellyfin, Emby, Nextcloud, Immich,
    PhotoPrism, OBS, and Linux thumbnailers
  - mitigation notes such as `--disable-decoder=magicyuv`
- HAProxy `CVE-2026-55203` / `CVE-2026-55204` indicators:
  - installed `haproxy` Debian-family packages with upstream-looking versions
    through `3.4.0` flagged for vendor-backport review
  - FastCGI backend configuration terms such as `fcgi-app`, `use-fcgi-app`,
    and `proto fcgi`
  - HTTP/2/HPACK exposure terms such as `alpn h2`, `hpack_dht_insert`, and
    `hpack_dht_defrag`
  - upstream fix commit IDs `5985276735777634d8c85f1d73bb7764aab0d6dd` and
    `9a6d1fe3f00d86ab4ea6ea6ea0a5d48fc058a513`
- libssh2 `CVE-2026-55200` client-exposure indicators:
  - installed `libssh2*` Debian-family packages
  - upstream-looking versions through `1.11.1` flagged for vendor-backport
    review
  - advisory/source terms including `ssh2_transport_read`, `packet_length`,
    `PR #2052`, fix commit `7acf3df`, and companion `CVE-2026-55199`
  - public PoC/research markers including `libssh2-cve-2026-55200-poc`,
    `cve_2026_55200_probe.c`, `libpwn_cve_2026_55200_server.py`,
    `libpwn_local_rce_harness.c`, and `libpwn_local_rce_exploit.py`
  - local workflow notes where libssh2 appears near SSH/SCP/SFTP clients such
    as curl, git, backup, deploy, clone, mirror, or artifact-fetch tooling
- PackageKit `CVE-2026-41651` local privilege-escalation indicators:
  - installed `packagekit*` Debian-family packages
  - upstream-looking versions `1.0.2` through `1.3.4` flagged for
    vendor-backport review
  - advisory/source terms including `InstallFiles`, `pk_transaction_set_state`,
    `transaction->cached_transaction_flags`, `TOCTOU`, `CWE-367`,
    and `src/pk-transaction.c`
  - public exploit/advisory provenance markers including `Pack2TheRoot`,
    `pack2theroot`, and `GHSA-f55j-vvr9-69xv`
- Cloud bucket hijacking posture indicators:
  - `Bucket Hijacking`, `attacker-controlled external storage bucket`,
    `active cloud data streams`, and globally unique bucket-name risk language
  - Google Cloud terms including `Cloud Logging sink`, `Pub/Sub subscription`,
    `Storage Transfer Service`, `storage.buckets.delete`,
    `storage.objects.delete`, and `logging.sinks.update`
  - AWS terms including `S3 bucket replication`, `Amazon Data Firehose`, and
    `DeleteBucket`
  - Azure terms including `Azure Monitor diagnostic settings` and
    `Microsoft.Storage/storageAccounts/delete`
  - mitigation terms including `VPC Service Controls`, `Service Control
    Policies`, trusted organizational boundaries, and account-regional S3
    namespaces
- MCP Python SDK `CVE-2026-52869` indicators:
  - PyPI `mcp` versions before fixed release `1.27.2`
  - advisory/source terms including `GHSA-jpw9-pfvf-9f58`, `CWE-639`,
    `SseServerTransport`, `StreamableHTTPSessionManager`, `Mcp-Session-Id`,
    `session_id`, `AccessToken.subject`, and `BearerAuthBackend`
  - SSE or stateful Streamable HTTP transport terms near bearer/OAuth/
    authenticated-principal configuration
  - hosted or multi-tenant MCP client notes where per-user subject isolation is
    required instead of only shared OAuth `client_id`
- Amazon Q Developer / AWS Language Servers workspace MCP indicators:
  - AWS bulletin `2026-047-AWS`, `CVE-2026-12957`, `CVE-2026-12958`,
    `GHSA-6v3r-4p5c-mrp5`, and `GHSA-xhcr-j4j9-3gh7`
  - Amazon Q plugin versions before fixed releases for VS Code, JetBrains,
    Eclipse, and Visual Studio
  - `.amazonq/mcp.json`, `mcpServers`, `command`, and `args` entries that can
    launch local MCP server processes from a workspace
  - AWS credential inheritance terms such as `AWS_ACCESS_KEY_ID`,
    `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, cloud CLI tokens, API keys,
    and SSH agent sockets
  - `aws sts get-caller-identity` / shell or curl collection behavior and
    symlink trust-boundary language
- ShapedPlugin Pro WordPress supply-chain indicators:
  - affected Pro plugin slugs `woo-product-slider-pro`, `testimonial-pro`, and
    `smart-show-post-pro`
  - `LicenseLoader.php`, `install-persistent.php`, fake
    `woocommerce-subscription` / `woocommerce-notification` plugin paths, and
    REST endpoint `/wp-json/wc/v3/settings/apply`
  - C2/exfil infrastructure `194.76.217[.]28:2871`,
    `generate[.]2faplugin[.]org`, and vendor update host
    `account.shapedplugin[.]com`
  - 2FA secret markers, login-bypass MD5, and reported loader SHA-256
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
- PostCSS-lookalike Windows RAT indicators:
  - package names `postcss-minify-selector-parser`,
    `postcss-minify-selector`, and `aes-decode-runner-pro`
  - `settings.ps1`, `update.vbs`, `loader.py`, Nuitka `.pyd` module names,
    `wscript.exe`, and publisher marker `abdrizak`
  - C2/downloader markers `nvidiadriver[.]net` and `95.216.92[.]207:8080`
  - Chrome credential, Chrome extension, and app-bound encryption theft terms
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
- Island / THN Adblock for YouTube browser-extension indicators:
  - live extension ID `cmedhionkhpnakcndndgjdbohmhepckk`
  - related removed extension IDs `onomjaelhagjjojbkcafidnepbfkpnee`,
    `ogcaehilgakehloljjmajoempaflmdci`, and
    `gekoepiplklhniacchbbgbhilidiojmb`
  - `api.adblock-for-youtube.com`, `get.adblock-for-youtube.com`,
    `api.extensionplay.com`, and Unistream infrastructure strings
  - `scripletsRules`, `trusted-create-element`, MAIN-world script injection,
    and weak full-URL `youtube.com` gate terms
- Aikido / BleepingComputer JetBrains Marketplace AI-key stealer indicators:
  - exact reported JetBrains plugin IDs such as `org.sm.yms.toolkit` and
    `com.dp.git.ai.tool`
  - reported exfiltration endpoint indicators including
    `39.107.60[.]51/api/software/key`
  - DFIR Radar's June 25 implementation markers including
    `F48D2AA7CF341F782C1D`, `BaseUtil.request()`, and `save()`/Apply plaintext
    HTTP POST behavior
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
  - GBHackers-reported SHA-1 values for GentleKiller, HexKiller,
    ThrottleBlood, HavocKiller, and OxideHarvest artifacts
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
  - ESET-reported EDR-killer suite markers including `GentleKiller`,
    `GentlemenCollection`, `HexKiller`, `ThrottleBlood`, `HavocKiller`,
    `OxideHarvest`, `UnknownKiller`, `PoisonKiller`, BYOVD behavior, fake
    version/signature metadata, abused driver markers such as `BdApi` and
    `havoc.sys`, and named abused-driver or impersonation filenames including
    `Kasps.exe`, `G11.sys`, `Avast.exe`, `Sent.exe`, `Sophos.exe`, and
    `buildx641.exe`
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
- Delphos Labs DirtyCBC / Linux RxGK decrypt-before-MAC analysis:
  https://delphoslabs.com/blog/36142374-e1fe-80a9-9456-d3c64df81bd5/%20linux-rxgk-decrypt-mac
- JFrog DirtyClone / CVE-2026-43503 analysis:
  https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
- The Hacker News DirtyClone / Copy Fail summary:
  https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html
- MatheuZ Security Trend Micro BMHook/TMHook reload bypass analysis:
  https://matheuzsecurity.github.io/hacking/trendmicro-bmhook-tmhook-reload-bypass/
- System Register Hijacking / ret2entry paper:
  https://kylebot.net/papers/ret2entry.pdf
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
- JFrog Shai-Hulud / Hades Leo/RStreams and Backstage npm analysis:
  https://research.jfrog.com/post/shai-hulud-miasma-alright-lets-see-if-this-works/
- BleepingComputer AtomicArch / AUR compromise summary:
  https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/
- Tenet Agentjacking Sentry/MCP writeup:
  https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/
- Cyber Security News Agentjacking summary:
  https://cybersecuritynews.com/agentjacking-attack-hijacks-ai-coding-agent/
- JFrog Solana FakeFix / CMS Windows loader report:
  https://research.jfrog.com/post/solana-fakefix/
- The Hacker News / JFrog PostCSS-lookalike Windows RAT summary:
  https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
- Socket GlassWASM Open VSX extension report:
  https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
- Island BadBlocker / Adblock for YouTube extension analysis:
  https://www.island.io/blog/badblocker-11-million-users-one-server-call-away-from-compromise
- The Hacker News Adblock for YouTube extension summary:
  https://thehackernews.com/2026/06/chrome-ad-blocker-with-10m-installs.html
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
- Supply Chain Attack incident catalog, ts-grok npm malware:
  https://supplychainattack.org/incident/malware-in-ts-grok-jjsh0j
- GitHub Advisory Database, GHSA-qp73-r9hh-6vq9 / ts-grok npm malware:
  https://github.com/advisories/GHSA-qp73-r9hh-6vq9
- Supply Chain Attack incident catalog, signup-embedder npm malware:
  https://supplychainattack.org/incident/malware-in-signup-embedder-1pgybu
- GitHub Advisory Database, GHSA-8j4q-hx83-pfq9 / signup-embedder npm malware:
  https://github.com/advisories/GHSA-8j4q-hx83-pfq9
- Checkmarx ChainVeil / SuccessKey npm supply-chain report:
  https://checkmarx.com/zero-post/chainveil-a-malicious-npm-supply-chain-attack-by-successkey/
- JFrog VS Code autorun / blockchain dead-drop npm hijack report:
  https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
- Nextron Research X post on Go packages reusing the JFrog fake-font payload:
  https://x.com/nextronresearch
- Supply Chain Attack incident catalog, latest npm malware batch:
  https://supplychainattack.org/
- Supply Chain Attack incident catalog, free-claude npm malware:
  https://supplychainattack.org/incident/malware-in-free-claude-7fjbqi
- GitHub Advisory Database, GHSA-fgqv-2jmm-2p39 / search-from-search npm malware:
  https://github.com/advisories/GHSA-fgqv-2jmm-2p39
- Supply Chain Attack incident catalog, search-from-search npm malware:
  https://supplychainattack.org/incident/malware-in-search-from-search-1jc4kr
- Panther OtterCookie npm campaign:
  https://panther.com/blog/tracking-an-ottercookie-infostealer-campaign-across-npm
- SafeDep Astro config blockchain C2 supply-chain report:
  https://safedep.io/astro-config-blockchain-c2-supply-chain/
- The Hacker News OpenClaw prompt-injection and agent-phishing report:
  https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html
- Microsoft Security AutoJack research:
  https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/
- The Hacker News AutoJack / AutoGen Studio package analysis:
  https://thehackernews.com/2026/06/autojack-attack-lets-one-web-page.html
- The Hacker News DifyTap cross-tenant AI data exposure summary:
  https://thehackernews.com/2026/06/researchers-detail-difytap-flaws-in.html
- SecurityWeek DifyTap data exposure summary:
  https://www.securityweek.com/data-exposure-flaws-threaten-dify-ai-platform-powering-over-1-million-apps/
- GitHub Security Advisory GHSA-x223-p2gf-v735 / Langflow CVE-2026-55450:
  https://github.com/langflow-ai/langflow/security/advisories/GHSA-x223-p2gf-v735
- IBM Security Bulletin / Langflow CVE-2026-10561 PythonREPL RCE:
  https://www.ibm.com/support/pages/node/7277242
- IBM Security Bulletin / Langflow CVE-2026-7664 webhook/MCP authorization bypass:
  https://www.ibm.com/support/pages/node/7277243
- SecurityOnline Langflow RCE summary:
  https://securityonline.info/langflow-rce-vulnerability/
- Imperva Laravel Livewire CVE-2025-54068 credential-theft campaign report:
  https://www.imperva.com/blog/cve-2025-54068-laravel-livewire-credential-theft-campaign-6000-applications-compromised/
- Synacktiv Livewire RCE through unmarshaling technical disclosure:
  https://www.synacktiv.com/en/publications/livewire-remote-command-execution-through-unmarshaling
- NVD CVE-2025-54068:
  https://nvd.nist.gov/vuln/detail/CVE-2025-54068
- Helge Sverre Livewire honeypot first-60-hours writeup:
  https://helgesver.re/articles/livewire-honeypot-first-60-hours
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
- ESET GentleKiller EDR-killer framework analysis:
  https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
- Infosecurity Magazine GentleKiller summary:
  https://www.infosecurity-magazine.com/news/gentlekiller-gentlemen-ransomware/
- GBHackers Gentlemen RaaS evasion suite summary:
  https://gbhackers.com/gentlemen-raas-unifies-evasion-suite/
- Zscaler ThreatLabz Edgecution / Payouts King analysis:
  https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution
- Huntress Heaven's Gate defensive overview:
  https://www.huntress.com/cybersecurity-101/topic/what-is-heavens-gate
- Unit 42 PAN-OS CVE-2026-0257 active exploitation brief:
  https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/
- The Hacker News PAN-OS GlobalProtect CVE-2026-0257 summary:
  https://thehackernews.com/2026/06/palo-alto-warns-of-active-exploitation.html
- BleepingComputer / CISA Joomla JCE CVE-2026-48907 active exploitation:
  https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-joomla-plugin-flaw-by-friday/
- Censys Joomla SP Page Builder CVE-2026-48908 advisory:
  https://censys.com/advisory/cve-2026-48908/
- Cyber Security News Splunk Enterprise CVE-2026-20253 active exploitation:
  https://cybersecuritynews.com/splunk-enterprise-vulnerability-exploit/
- Cyber Security News / watchTowr Splunk Enterprise sidecar chain summary:
  https://cybersecuritynews.com/splunk-enterprise-pre-auth-rce-chain-exposes/
- SecurityWeek REDCap internet-exposure / UNC6508 report:
  https://www.securityweek.com/majority-of-internet-accessible-redcap-servers-outdated/
- CISA Fortinet device hardening alert:
  https://www.cisa.gov/news-events/alerts/2026/06/18/cisa-urges-hardening-fortinet-devices-after-reports-credential-exposure
- TechRadar summary of Fortinet/FortiGate credential exposure reporting:
  https://www.techradar.com/pro/security/fortinet-firewalls-hit-by-huge-password-stealing-attack-around-75-000-users-possibly-affected
- SOCRadar FortiBleed / FortigateSniffer whitepaper landing page:
  https://socradar.io/resources/whitepapers/dismantling-fortibleed-inside-a-russian-fortinet-compromise-operation/
- Cyber Security News FortigateSniffer / FortiBleed tooling summary:
  https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/
- Cyber Security News FortiBleed scale and attack-chain summary:
  https://cybersecuritynews.com/fortibleed-attack-fortigate-firewalls/
- CISA Known Exploited Vulnerabilities catalog:
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA Known Exploited Vulnerabilities JSON feed, catalog version `2026.06.23`:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- BleepingComputer / CISA Ubiquiti and Lantronix KEV exploitation warning:
  https://www.bleepingcomputer.com/news/security/cisa-warns-of-max-severity-ubiquiti-flaws-exploited-in-attacks/
- Bishop Fox UniFi OS unauthenticated RCE chain detection and analysis:
  https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis
- The Hacker News PTC Windchill/FlexPLM `CVE-2026-12569` KEV/web shell summary:
  https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html
- PTC advisory `CS473270`:
  https://www.ptc.com/en/support/article/CS473270
- NVD `CVE-2026-12569` record:
  https://nvd.nist.gov/vuln/detail/CVE-2026-12569
- Cyber Security News python.org release-management API vulnerability summary:
  https://cybersecuritynews.com/critical-python-org-vulnerability/
- Lantronix EDS5000 latest firmware page:
  https://ltrxdev.atlassian.net/wiki/spaces/LTRXTS/pages/2538438657/Latest%2BFirmware%2Bfor%2Bthe%2BEDS5000%2Bseries%2BEDS5008%2BEDS5016%2BEDS5032
- NVD CVE-2026-20230 record:
  https://nvd.nist.gov/vuln/detail/CVE-2026-20230
- Cisco Unified Communications Manager WebDialer SSRF advisory:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW
- Google Threat Intelligence Group, Cisco Catalyst SD-WAN Manager zero-day exploitation:
  https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager/
- Cyber Security News, Cisco Catalyst SD-WAN Manager 0-day summary:
  https://cybersecuritynews.com/cisco-catalyst-sd-wan-manager-0-day/
- SecurityOnline Cisco SD-WAN zero-day summary:
  https://securityonline.info/cisco-sd-wan-zero-day/
- Microsoft MSRC Update Guide for `CVE-2026-45504`:
  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504
- hawktrace public PoC repository for `CVE-2026-45504`:
  https://github.com/hawktrace/CVE-2026-45504
- Hawktrace Exchange `CVE-2026-45504` WOPI file-read analysis:
  https://hawktrace.com/blog/CVE-2026-45504/
- Aretiq AI analysis for `CVE-2026-45502` Exchange EWS InstallApp SSRF:
  https://aretiq.ai/research/vul260622-cve-2026-45502-microsoft-exchange-server-ews-installapp-server-side-request-forgery/
- Microsoft MSRC Update Guide for `CVE-2026-45502`:
  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502
- The Hacker News Operation Endgame / SocGholish disruption report:
  https://thehackernews.com/2026/06/operation-endgame-disrupts-socgholish.html
- BleepingComputer Operation Endgame Amadey/StealC disruption update:
  https://www.bleepingcomputer.com/news/security/amadey-stealc-malware-operations-disrupted-in-operation-endgame-action/
- Proofpoint and IBM X-Force StealC / Operation Endgame technical context:
  https://www.proofpoint.com/us/blog/threat-insight/stealc-you-later-proofpoint-and-ibm-x-force-support-operation-endgame
- FBI IC3 PSA on malicious traffic distribution systems:
  https://www.ic3.gov/PSA/2026/PSA260618
- Ars Technica Microsoft Crypto Clipper USB worm report:
  https://arstechnica.com/security/2026/06/microsoft-spots-new-self-propagating-malware-for-stealing-cryptocurrency/
- ANY.RUN EvilTokens Microsoft OAuth device-code phishing analysis:
  https://any.run/cybersecurity-blog/eviltokens-ghost-code-analysis/
- Netcraft BlueKit Browser-in-the-Middle phishing analysis:
  https://www.netcraft.com/blog/bluekit-phishing-as-a-service-threat
- BleepingComputer BlueKit BitM phishing summary:
  https://www.bleepingcomputer.com/news/security/bluekit-phishing-kit-adopts-browser-in-the-middle-for-login-theft/
- The Hacker News TonRAT Photo ZIP hospitality phishing summary:
  https://thehackernews.com/2026/06/microsoft-warns-of-photo-zip-phishing.html
- SOC Prime technical analysis of suspicious emails targeting the hotel industry:
  https://socprime.com/active-threats/technical-analysis-of-suspicious-emails-targeting-the-hotel-industry/
- Broadcom/Symantec Backdoor.Mistic / ModeloRAT access-broker analysis:
  https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
- SecurityWeek Mistic RAT ransomware access-broker summary:
  https://www.securityweek.com/new-mistic-rat-opens-door-to-several-ransomware-families/
- Zscaler ThreatLabz MLTBackdoor technical analysis:
  https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor
- BleepingComputer macOS ClickFix / AMOS DMG campaign summary:
  https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
- SentinelOne macOS.Gaslight Rust backdoor analysis:
  https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
- The Hacker News macOS.Gaslight summary:
  https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html
- SecurityAffairs macOS.Gaslight summary:
  https://securityaffairs.com/194256/malware/macos-gaslight-north-korea-linked-malware-that-tries-to-gaslight-the-analyst.html
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
- The Hacker News AryStinger router/NAS proxy network summary:
  https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html
- QiAnXin XLab AryStinger technical analysis and IOC list:
  https://blog.xlab.qianxin.com/arystinger-botnet-hijacks-legacy-routers-for-global-attacks-en/
- The Hacker News Squidbleed `CVE-2026-47729` summary:
  https://thehackernews.com/2026/06/29-year-old-squid-proxy-bug-squidbleed.html
- BleepingComputer PixelSmash / FFmpeg `CVE-2026-8461` summary:
  https://www.bleepingcomputer.com/news/security/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video-decoder/
- Malwarebytes PixelSmash / FFmpeg `CVE-2026-8461` summary:
  https://www.malwarebytes.com/blog/news/2026/06/pixelsmash-flaw-turns-video-files-into-attack-tools
- JFrog PixelSmash technical analysis:
  https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/
- SecurityOnline HAProxy `CVE-2026-55203` / `CVE-2026-55204` summary:
  https://securityonline.info/haproxy-vulnerabilities-cve-2026-55203/
- HAProxy upstream FastCGI demux record-length fix:
  https://github.com/haproxy/haproxy/commit/5985276735777634d8c85f1d73bb7764aab0d6dd
- HAProxy upstream HPACK dynamic-table NULL-check fix:
  https://github.com/haproxy/haproxy/commit/9a6d1fe3f00d86ab4ea6ea6ea0a5d48fc058a513
- libssh2 upstream PR #2052, additional packet-length boundary checks:
  https://github.com/libssh2/libssh2/pull/2052
- NixOS security tracker issue for libssh2 `CVE-2026-55199` and
  `CVE-2026-55200`:
  https://github.com/NixOS/nixpkgs/issues/532920
- bikini/exploitarium libssh2 `CVE-2026-55200` public PoC tree:
  https://github.com/bikini/exploitarium/tree/main/libssh2-cve-2026-55200-poc
- NVD `CVE-2026-41651` PackageKit record:
  https://nvd.nist.gov/vuln/detail/CVE-2026-41651
- GitHub Advisory `GHSA-f55j-vvr9-69xv` / PackageKit `CVE-2026-41651`:
  https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv
- Openwall oss-security PackageKit `CVE-2026-41651` disclosure:
  http://www.openwall.com/lists/oss-security/2026/04/22/6
- Unit 42 cloud bucket hijacking risk analysis:
  https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/
- Cyber Security News bucket hijacking summary:
  https://cybersecuritynews.com/bucket-hijacking-attack/
- GitHub Advisory `GHSA-jpw9-pfvf-9f58` / MCP Python SDK `CVE-2026-52869`:
  https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58
- SkyPoC MCP Python SDK `CVE-2026-52869` analysis:
  https://skypoc.wordpress.com/2026/06/10/cve-2026-52869/
- The Hacker News Pedit COW / `CVE-2026-46331` summary:
  https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
- NVD `CVE-2026-46331` record:
  https://nvd.nist.gov/vuln/detail/CVE-2026-46331
- Red Hat Security Bulletin RHSB-2026-008:
  https://access.redhat.com/security/vulnerabilities/RHSB-2026-008
- Ubuntu `CVE-2026-46331` tracker:
  https://ubuntu.com/security/CVE-2026-46331
- Debian `CVE-2026-46331` tracker:
  https://security-tracker.debian.org/tracker/CVE-2026-46331
- Positive Technologies DBugs `CVE-2026-23111` record:
  https://dbugs.ptsecurity.com/vulnerability/CVE-2026-23111
- Linux stable `CVE-2026-23111` nf_tables fix commit:
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=8c760ba4e36c750379d13569f23f5a6e185333f5
- Baba01hacker666 public `CVE-2026-23111` PoC/checker repository:
  https://github.com/Baba01hacker666/CVE-2026-23111
- FOFA Gogs product fingerprint query:
  https://en.fofa.info/result?qbase64=YXBwPSJHb2dzIg==
- Jorian Woltjer public Gogs RCE PoC reference:
  https://gist.github.com/JorianWoltjer/4b72063338b27140f4439c524d98f2b9
- Wordfence ShapedPlugin Pro supply-chain compromise PSA:
  https://www.wordfence.com/blog/2026/06/psa-supply-chain-compromise-targets-shapedplugin-backdoored-pro-plugins-distributed-via-official-channels/
- The Hacker News ShapedPlugin Pro supply-chain compromise summary:
  https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html
