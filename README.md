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
