# linux-supply-chain-guard

`linux-supply-chain-guard` is a read-only Linux host checker for developers and
incident responders reviewing supply-chain exposure on workstations, CI
runners, and build hosts.

It checks local host posture related to the May 2026 Linux supply-chain response
lane, including Fragnesia / `CVE-2026-46300` kernel exposure, risky module
state, and known developer-tooling persistence paths reported in public
Shai-Hulud / Here We Go Again analysis.

This project also tracks urgent exposed-Linux-server advisories as operator
guidance when they intersect supply-chain response hosts. NGINX Rift /
`CVE-2026-42945` is currently documented as advisory-only context; this guard
does not yet perform NGINX version or rewrite-module configuration detection.

## Safety stance

- Read-only checks by default.
- No exploit testing.
- No malware execution.
- No automatic cleanup.
- No token revocation.
- No claim that a host is clean.
- Secret files are detected by path only; contents are not printed.
- No telemetry, upload, or maintainer-side collection of scan results.

## Privacy

This guard does not save, collect, upload, or transmit user data. It reads local
host metadata and reports findings to the terminal, or to a local report path
only when the operator explicitly provides `--report`.

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
- Common developer credential surfaces by presence only.

## Advisory-only Watch Items

- NGINX Rift / `CVE-2026-42945`: heap buffer overflow in
  `ngx_http_rewrite_module`, reported against NGINX Open Source and NGINX Plus
  versions `0.6.27` through `1.30.0`. Public reporting says exploitation
  attempts are active in the wild. Worker-process crash is exploitable; possible
  RCE depends on vulnerable rewrite configuration and ASLR being disabled.
  Patch exposed NGINX deployments through vendor packages. This guard currently
  documents the risk but does not automatically inspect NGINX builds.

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
- The Hacker News on NGINX CVE-2026-42945 active exploitation:
  https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html
- The Register on NGINX Rift exploitation:
  https://www.theregister.com/security/2026/05/18/nginx-rift-attackers-waste-no-time-targeting-exposed-servers/
