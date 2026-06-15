# Maintainer Notes

Current public repo:
https://github.com/Dragon-Lady/linux-supply-chain-guard

Runtime: Node.js >= 18

Safety stance:

- Read-only scanner.
- No dependencies.
- No exploit testing.
- No file removal.
- No token revocation.
- No claims that a host is clean.

## Core Commands

```powershell
cd C:\path\to\linux-supply-chain-guard
npm test
node bin\linux-supply-chain-guard.js --json
npm run canary:socket-firewall
npm run canary:socket-firewall:log
```

`npm run canary:socket-firewall` requires Socket Firewall (`sfw`) to be
installed on the canary host first with `npm install -g sfw`. See
`docs/socket-firewall-canary.md`.

Windows scheduled canary task:
`LinuxSupplyChainGuard-SocketFirewallCanary`

## Initial Scope

- AlmaLinux Fragnesia / `CVE-2026-46300` kernel posture.
- ITScape / `CVE-2026-46316` ARM64 KVM exposure posture.
- Loaded `esp4`, `esp6`, and `rxrpc` module state.
- Temporary module blacklist visibility.
- Known Shai-Hulud / Here We Go Again Linux persistence paths.
- `/tmp/transformers.pyz` presence and SHA-256 when present.
- Developer credential surfaces by path presence only.
- PCPJack / Chisel SMTP relay host-residue indicators from Hunt.io and
  Security Affairs: `/var/tmp/.xs`, `xsync`, Sliver client config paths, relay
  CSV/verifier files, and high-signal relay IP/path strings.

## Public Response Rules

- Do not ask users to paste secrets, `.env` files, private keys, tokens, or full logs.
- Do not claim this tool proves a host is clean.
- If critical findings are present, advise containment first.
- Do not advise revoking tokens from the suspected infected machine.
- Credential rotation should happen from a clean machine.
- If payload execution, persistence, privilege escalation, or secret exposure is plausible, recommend rebuild/reimage.
