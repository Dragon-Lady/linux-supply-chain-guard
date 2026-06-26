# Recovery Playbook

Use this sequence when `linux-supply-chain-guard` reports critical findings or
when a Linux host may have executed compromised package payloads.

## 1. Stop Activity

- Stop package installs, builds, test runners, dev servers, and deployment jobs.
- Do not run cleanup commands from a suspected infected host.
- Do not revoke tokens from the suspected infected host first.

## 2. Contain

- Disconnect the host from the network if payload execution is plausible.
- Preserve scanner output, package manifests, lockfiles, install logs, shell
  history, systemd unit state, and payload metadata.
- Preserve `/tmp/transformers.pyz` if present. Do not execute it.
- Preserve suspicious service files and scripts such as `gh-token-monitor` and
  `pgsql-monitor` paths before removal.

## 3. Patch Host Risk

- For Fragnesia / `CVE-2026-46300`, apply vendor patched kernels and reboot.
- If reboot is not immediately possible, use only vendor-approved temporary
  mitigations for `esp4`, `esp6`, and `rxrpc`.
- Do not rely on mitigations if the host requires IPsec ESP or AFS/rxrpc
  workloads; use patched kernels.
- For ITScape / `CVE-2026-46316`, prioritize ARM64 KVM hosts that run
  untrusted or multi-tenant guests. Apply vendor-fixed kernels, reboot
  hypervisors, and verify distro/cloud backport status if the running kernel is
  below upstream `6.15.0`.
- For DirtyCBC / Linux RxGK page-cache poisoning leads, verify vendor-fixed
  kernel status and reboot after patching. Do not rely on package hashes or
  direct disk reads alone as proof of safety because the reported primitive
  modifies page cache rather than the on-disk file.
- For DirtyClone / `CVE-2026-43503`, verify the host kernel includes the full
  DirtyFrag-family patch series and reboot after patching. If immediate
  patching is not possible, reduce temporary exposure by blocking unprivileged
  `CAP_NET_ADMIN` acquisition through user namespaces and by using
  vendor-approved `esp4`, `esp6`, and `rxrpc` mitigations only where those
  workloads are not required.
- For NGINX Rift / `CVE-2026-42945`, patch exposed NGINX Open Source or NGINX
  Plus deployments through vendor packages. Prioritize internet-facing reverse
  proxies, package mirrors, CI/build hosts, and self-hosted developer services.
  Review rewrite-module configuration separately; this guard does not yet
  inspect NGINX versions or rewrite rules.
- For Sudo `CVE-2026-35535`, patch sudo through distro packages on Linux
  workstations, WSL environments, CI runners, and build hosts. Treat it as a
  local privilege-escalation amplifier: it is not remote by itself, but it can
  turn compromised package execution or a low-privilege shell into root.
  Verify package status with the distro's security tracker; this guard does not
  yet inspect installed sudo versions.

## 4. Rotate From A Clean Machine

Before revoking GitHub tokens, verify and remove known dead-man-switch
persistence from a trusted recovery posture when present.

Rotate credentials from a separate trusted device:

- GitHub personal access tokens, OAuth grants, deploy keys, and Actions secrets
- npm, PyPI, RubyGems, and package publishing credentials
- AWS, GCP, Azure, Vault, Kubernetes, and other cloud credentials
- SSH keys and CI/CD secrets

## 5. Rebuild And Verify

If payload execution, persistence, privilege escalation, or secret access is
confirmed, rebuild or reimage from a clean baseline. Reinstall dependencies from
reviewed lockfiles pinned away from known-bad package versions.
