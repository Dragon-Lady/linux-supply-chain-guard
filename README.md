# linux-supply-chain-guard

`linux-supply-chain-guard` is a read-only Linux host checker for developers and
incident responders reviewing supply-chain exposure on workstations, CI
runners, and build hosts.

It checks local host posture related to the May 2026 Linux supply-chain response
lane, including Fragnesia / `CVE-2026-46300` kernel exposure, risky module
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
local operator notifications only.

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
- GitHub Advisory npm malware packages with all versions affected:
  - `csc154-internall-depend`
  - `@validate-sdk/v2`
  - `google-cloud-secret-manager-config-poc`
- Panther OtterCookie npm indicators:
  - package names including `bjs-biginteger`, `bjs-lint-builder(s)`,
    `hjs-lint-builders`, `sjs-builder(s)`, and `npm-doc-builder`
  - Vercel-hosted C2 domains used for config retrieval and file upload
  - install-time `node test.js` / `postinstall` behavior markers
- Hades / Miasma PyPI indicators:
  - affected package versions including `langchain-core-mcp`, `openai-mcp`,
    `instructor-mcp`, `tiktoken-mcp`, `ray-mcp-server`, and reported
    bioinformatics package versions
  - `*-setup.pth`, `_index.js`, `.bun_ran`, `oven-sh/bun/releases/download`,
    `subprocess.run`, and `sys.path` loader patterns
  - native `.abi3.so` extension layouts paired with `_index.js`
  - GitHub/CI markers including `Run Copilot`, `format-results`, and
    `Hades - The End for the Damned`
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
- Oracle PeopleSoft / CVE-2026-35273 indicators:
  - PeopleSoft PeopleTools `8.61` or `8.62` version references
  - PSEMHUB/PSIGW route references such as `/PSEMHUB/hub` and
    `/PSIGW/HttpListeningConnector`
  - JSP files and unexpected transaction/storage paths under `PSEMHUB.war`
  - MeshCentral masquerade filenames such as `meshagent64-azure-ops.exe`
  - ShinyHunters campaign network indicators including `azurenetfiles.net`
  - `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT`
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
- JFrog Solana FakeFix / CMS Windows loader report:
  https://research.jfrog.com/post/solana-fakefix/
- GitHub Advisory for `google-cloud-secret-manager-config-poc`:
  https://github.com/advisories/GHSA-g6v5-9xpp-6hpx
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
