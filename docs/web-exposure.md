# Local web configuration and webroot review

This check helps operators review management interfaces, cache/session stores
and webroot changes. It is enabled in the default scan, with webroot content
hashing enabled only by an explicit `--webroot` selection. It makes no network
requests, executes no target code, and changes no
service settings or target files. The existing `--report` option is the only
explicit report-writing operation.

The motivating research is [NorForge's October 19 Cairn investigation](https://norforge.com/blog/inside_cairn).
These checks address some general configuration and integrity risks. They do
not identify Cairn operators, detect all webshells, validate an exploit or claim
protection from that campaign. There is no established connection to the PHP
security release announced October 20. PHP readiness keeps its separate
unknown patch status.

## What is inspected

| Area | Supported evidence | Meaning |
| --- | --- | --- |
| Webmin/Usermin | `/etc/webmin/miniserv.conf`, `/etc/usermin/miniserv.conf`: bind and explicit TLS-off settings | Non-loopback listener declarations prompt access review. Missing bind follows the documented all-address default. Access lists, proxies and service activation are not verified. |
| Cockpit | `/etc/systemd/system/cockpit.socket` and `.conf` files under its `.d` directory: `[Socket]` `ListenStream` | Non-loopback declarations prompt review. Empty resets are handled within each file. Vendor units, other drop-ins and merged systemd state are not resolved. |
| Compose | Block-style service image, short-form ports and `network_mode` | Recognized admin/cache images with host networking or non-loopback published ports prompt review. `expose` alone is not treated as a host-published port. |
| Redis | `/etc/redis/redis.conf`, `/etc/redis.conf` | Non-loopback bind, explicit protected-mode disablement, explicit empty legacy password or passwordless default-user declarations. Effective ACLs and authentication are unknown. |
| Memcached | `/etc/memcached.conf`, one option per line | Non-loopback bind, enabled UDP or an unresolved bind restriction. An explicit Unix socket disables these network findings. Startup overrides are unknown. |
| PHP sessions | `/etc/php.ini`, `/usr/local/etc/php.ini`, `.ini` files under `/etc/php` and `/usr/local/etc/php` | Network session-handler declarations; for local file sessions, directory permissions allowing other users to list entries or write without a sticky bit. This configuration check does not open session files. |
| Webroot integrity | All regular files beneath each explicit `--webroot` | SHA-256, byte size and Unix mode compared with a selected baseline. Added, removed, content-changed and permission-changed files are review findings. |

Compose discovery covers `/opt`, `/srv` and `/var/www`. It skips dependency,
VCS and build-output directories: `.git`, `.hg`, `.svn`, `node_modules`,
`vendor`, `.venv`, `venv`, `dist`, `build`, `coverage` and `.next`.
Use repeatable `--web-compose FILE` for files elsewhere inside the target root.
Recognized image names are `adminer`, `phpmyadmin`, `phpmyadmin/phpmyadmin`,
`portainer/portainer-ce`, `portainer/portainer-ee`, `redis` and `memcached`,
including supported Docker Hub prefixes. Arbitrary custom images, including
ambiguous images named Cairn, are outside the image-identification scope.

The Compose reader supports ordinary block service maps and short port lists.
Includes, inheritance, anchors, duplicate keys, flow maps/lists, long-form port
maps and unresolved image/network/port substitutions produce incomplete
coverage. It never runs Compose or expands configuration. Redis includes and
ACL files are likewise flagged for separate review instead of being loaded.
Configuration is examined per file: an override elsewhere may change a finding.
PHP FPM pool overrides, `.user.ini`, application overrides and container runtime
configuration are not evaluated as session configuration.

All output keeps `runtimeExposure: "unknown"`. A non-loopback address may be
private or firewalled. Loopback is not proof of safety when another proxy or
service can reach it. Findings do not establish internet exposure, missing
authentication, a compromised host or a patched host. Missing optional files
mean nothing was observed at those paths, not that the service is absent.

## Compare webroot changes

Choose the actual document root. Paths refer to the inspecting machine; for a
mounted target, include its mount prefix. Multiple `--webroot` options are
supported, and every selected directory must lie inside the target root.

First inspect a deployment whose contents you can validate against a trusted
release or source. Save a private report outside every webroot:

```sh
linux-supply-chain-guard /mnt/recovered-root \
  --webroot /mnt/recovered-root/var/www/site \
  --report ./reviewed-webroot.json --json
```

The first scan reports `webroot-baseline-needed`. Review it before treating it
as trusted. Later compare the same logical webroot paths:

```sh
linux-supply-chain-guard /mnt/recovered-root \
  --webroot /mnt/recovered-root/var/www/site \
  --web-baseline ./reviewed-webroot.json --json
```

The baseline may be a prior full JSON report or its `webExposure.manifest`
object. The format is schema 1, SHA-256, with matching ordered root paths,
complete coverage, unique normalized relative file paths and valid hashes,
sizes and modes. Invalid, unreadable, linked or mismatched baselines make the
comparison incomplete. Baselines inside a selected webroot are refused.
The operator must verify baseline provenance; the tool does not sign, approve,
refresh or overwrite a baseline. Protect it independently of the website.

Selected webroots have no implicit dependency/build/hidden-file exclusions:
changes in uploaded files, `.htaccess`, `.user.ini`, dependencies or built
assets all matter. An explicit `--exclude` makes that inspection incomplete.
Select document roots carefully: hashing reads every regular file selected,
including private/session data if it was placed inside that document root.
Timestamps alone are not used as evidence of a change. Ownership, ACLs,
extended attributes, runtime memory and files outside the selected roots are
not compared. A matching baseline is not proof that a site is uncompromised;
ordinary authorized deployments also produce differences.

`comparison` is `not-requested`, `matched`, `changed` or `incomplete`.
`manifest.complete` covers the selected webroots only. An unrelated config gap
can coexist with a complete webroot manifest; overall coverage remains
incomplete. If webroot traversal is incomplete, no removal or clean comparison
is asserted from the partial inventory.

## Limits and privacy

This lane uses Linux `/proc/self/fd` and directory descriptors to anchor reads.
The explicitly selected root may be a symlink; links discovered beneath it are
not followed. A changed file is discarded. Use a stable, read-only filesystem
snapshot when concurrent changes are possible: this is not an atomic snapshot.

Defaults per scan: 50,000 directory entries, 10,000 file reads, 128 MiB total,
1 MiB per config, 8 MiB per webroot file, 32 directory levels, 2,000 findings
and 2,000 configuration records, and a cooperative 10-second budget. Reading
the explicit baseline has a separate bounded 8 MiB allowance. Individual
filesystem calls can take longer than the cooperative budget. At most 40 gap
samples are retained. Exhaustion, unsupported input, missing required input,
unreadable paths, special files and skipped symlinks produce
`web-exposure-incomplete`, overall incomplete coverage and exit code 3 unless
an existing higher-priority finding applies (4 > 2 > 3 > 1 > 0).

Findings contain paths and fixed descriptions, not source lines, passwords,
session URLs, session IDs, access-list values, image tags or raw error text.
Webroot manifests contain file hashes and metadata, which may still reveal
sensitive deployment details. Keep full reports private. `--report` creates a
new file with mode 0600; shell redirection uses the shell's own permissions.
The scanner does not quarantine files, patch software or validate remote URLs.

## Configuration references

- [Webmin access, listener and TLS configuration](https://webmin.com/docs/modules/webmin-configuration/)
- [Cockpit listener declarations and resets](https://docs.cockpit-project.org/cockpit-guide/latest/guide/listen.html)
- [Docker Compose service and published-port syntax](https://docs.docker.com/reference/compose-file/services/#ports)
- [Redis network security, protected mode and authentication](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
- [Memcached interfaces, UDP and Unix sockets](https://docs.memcached.org/serverguide/configuring/)
- [PHP session configuration and file-directory syntax](https://www.php.net/manual/en/session.configuration.php)

References reviewed October 20, 2026. Tests use inert local fixtures; no live
attack infrastructure is contacted.
