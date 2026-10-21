# PHP readiness check

The default scan includes a read-only PHP inventory and deployment review.
It records evidence to help operators prepare for a security update. It does
not determine whether PHP is vulnerable, patched, running or internet-facing.

## Advisory snapshot: October 20, 2026

PHP announced two critical vulnerabilities rated CVSS 4.0 9.2, with a security
release scheduled for October 21 at 14:00 UTC (possibly earlier). Affected and
fixed versions were not disclosed in the advance notice. This is a dated
snapshot, not a live feed. Every result keeps `patchStatus: "unknown"`.

- Official release information: https://www.php.net/archive/2026.php
- Further research updates: https://www.ox.security/blog/

The OX link is the general research index. No PHP-specific OX article was
verified for this snapshot. It is not evidence of an affected version or a fix.
If PHP evidence appears, consult the official release and your distribution or
hosting provider's advisory. This scanner cannot tell whether exploitation
occurred; it does not supply a mitigation or replace an update.

## Evidence and limits

| Evidence | What it establishes |
| --- | --- |
| Installed Debian/Ubuntu or Alpine package records | PHP-related package names and full vendor revisions, including extensions; package metadata is not a running-process check. Removed packages are ignored; held installed packages are included. |
| Common binary paths and links | A PHP CLI, CGI or FPM path exists. The scanner does not execute the file or resolve its version. |
| PHP and Apache module configuration paths | Configuration material exists. Its contents are not read, and service activation is unknown. |
| Composer requirements or platform overrides | The project declares PHP. The configured version may simulate another runtime and is never treated as an installed version. |
| Official PHP image declarations in Dockerfiles and block-style Compose files | A build stage or service declares PHP. The declaration may be unused; tags and digests are not inspected or resolved. |

Package databases: `/var/lib/dpkg/status` and `/lib/apk/db/installed` (the
explicit `/usr/lib/apk/db/installed` alternative is checked when `/lib` is a
link). Binary discovery lists `/usr/bin`, `/usr/sbin`, `/usr/local/bin` and
`/usr/local/sbin`. Configuration discovery covers `/etc/php`, `/etc/php-fpm.d`,
`/usr/local/etc/php`, `/usr/local/etc/php-fpm.d`, their common top-level INI/FPM
files, and `/etc/apache2/mods-available` and `mods-enabled` PHP entries.

Project declarations are discovered under `/opt`, `/srv`, `/var/www` and the
selected home directory when it lies inside the target root. For a mounted
root, use `--home` with a directory inside that mount. Project discovery skips
`.git`, `.hg`, `.svn`, `.next`, `dist`, `build`, `coverage`, `node_modules`,
`vendor`, `.venv` and `venv`. Those standard scope exclusions do not count as
inspection failures. Explicit `--exclude` paths do.

RPM databases, custom installation locations, custom image contents,
Kubernetes manifests, running containers, process memory, remote servers and
hosted sites are outside this check. Missing package metadata remains
`not-observed`. An empty inventory does not establish that PHP is absent.
File declarations are review leads, not a full Dockerfile/Compose validator.
Compose includes, aliases, merges, flow-style services and unresolved whole-image
variables, plus Dockerfile heredocs/custom escapes, produce an incomplete
inspection when encountered rather than being executed or expanded.

## Output and safety

Run the regular CLI; the check is enabled by default:

```sh
node bin/linux-supply-chain-guard.js /mnt/recovered-root --json
```

JSON adds `phpReadiness`, including the dated advisory, evidence records,
package database status, `patchStatus`, `presence`, and scoped coverage. Text
output always shows the unknown PHP patch status, including when no evidence
is found. Findings use `php-readiness-*` IDs and review severity. The check
does not assign critical severity to mere PHP presence.

Failed, changed, oversized, unsupported, symlinked or excluded inspection
candidates produce `php-readiness-incomplete`, top-level incomplete coverage
and exit code 3 unless an existing higher-priority finding applies. Existing
precedence remains 4 > 2 > 3 > 1 > 0. Symlinked binary/configuration paths may
be recorded as metadata only; their targets are not opened. Symlinks encountered
during recursive discovery are recorded as coverage gaps.

Reads are bounded and reject non-regular files and changed file identities.
Defaults: 50,000 directory entries, 2,000 candidate reads, 2,000 evidence
records, 2 MiB per project file, 32 MiB per package database, 64 MiB total reads,
24 levels of recursion and a cooperative 10-second budget. Individual
filesystem operations may take longer. Coverage includes counts and up to 40
gap samples. Read-only inspection is not an atomic snapshot; use a stable
mounted filesystem when concurrent hostile changes are suspected.

No PHP or package-manager execution, container API calls, network requests,
target writes, service restarts or automatic remediation. Configuration
contents, Composer scripts, raw image references and filesystem error text are
not included in this check's findings. Evidence paths and validated package
versions are included; keep reports private as usual.

## When the patch details are published

Update `data/php-readiness.json` from PHP's official release and relevant
distribution advisories, then implement and test the corresponding checks.
Changing the snapshot alone never turns an unknown result into a fixed verdict.
Keep distro revisions and backports separate from upstream version comparison.
Verify each serving FPM/Apache/CGI runtime and deployed container, including
whether it has loaded the update. CLI or Composer results cannot clear them.

Tests must cover affected, fixed, backported and unresolved versions, plus
multiple PHP branches, stale declarations and incomplete coverage. Publish
accurate release notes and verify the actual release artifact before preparing
a placard or quote-post that claims the added coverage.
