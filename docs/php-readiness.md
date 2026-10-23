# PHP readiness check

The default scan includes a read-only PHP inventory and deployment review.
It compares version evidence with a dated upstream security advisory. It does
not determine whether PHP is vulnerable, patched, running or internet-facing.

## Advisory snapshot: October 21, 2026

PHP released fixes for two critical vulnerabilities rated CVSS 4.0 9.2:

| Upstream branch | Affected upstream releases | First fixed release |
| --- | --- | --- |
| 8.2 | Earlier than 8.2.35 | 8.2.35 |
| 8.3 | Earlier than 8.3.36 | 8.3.36 |
| 8.4 | Earlier than 8.4.27 | 8.4.27 |
| 8.5 | Earlier than 8.5.12 | 8.5.12 |

- [CVE-2026-109618: OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
  concerns failed allocations, partially initialized state and unsafe cleanup.
  PHP confirms unauthenticated pre-application RCE on mod_php; evidence for
  exploitability differs across other SAPIs.
- [CVE-2026-109619: stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
  concerns request state reused by a persistent worker after its memory was
  freed. A subsequent request must reach a consumer before state resets.
  Confirmed session-lifecycle paths include mod_php and FPM.

PHP warns that web-serving installations are at risk. Only updating provides
a complete fix; disabling upload progress addresses only particular paths.
PHP 8.1 and older require maintained vendor backports or migration to a
supported branch. This scanner does not test exploit prerequisites or apply
configuration mitigations. Every result keeps `patchStatus: "unknown"`.

- Official release information: https://www.php.net/archive/2026.php
- Official changelog: https://www.php.net/ChangeLog-8.php
- OX research: https://www.ox.security/blog/php-cve-2026-109618-cve-2026-109619-what-to-do-before-the-details-drop/

The OX article contains pre-disclosure guidance. PHP's subsequently published
advisories establish the versions and fix details used here. The PHP archive
dates the releases October 21; the changelog headers observed during this check
were dated October 22. No timing inference is drawn from that discrepancy.

Vendor status is a dated observation, not a live feed. At this check, Ubuntu's
[first](https://ubuntu.com/security/CVE-2026-109618) and
[second](https://ubuntu.com/security/CVE-2026-109619) CVE pages showed relevant
PHP packages awaiting evaluation. Debian's two CVE tracker entries returned
404. Alpine's v3.21-v3.24 community security feeds had no matching CVE fix
entries. Exact source URLs are retained in `data/php-readiness.json`.
No distribution fixed revision was verified. Missing entries do not establish
that a package update or backport is unavailable. Consult the package vendor.

## Upstream comparison and backports

Each evidence record includes `upstreamAssessment`, separate from unknown
deployment `patchStatus`. These statuses describe version evidence only:

| Status | Meaning |
| --- | --- |
| `below-fixed-upstream` | The recognized branch's upstream version predates its listed fix. A vendor may have backported the patch. |
| `at-or-above-fixed-upstream` | The numeric version reaches that branch's fix threshold. It does not prove that an image exists, contains that version, or is deployed. |
| `unsupported-upstream` | A recognized older PHP branch lacks ongoing upstream support; maintained vendor coverage requires separate verification. |
| `unknown` | No exact final runtime version is available, the package name and version disagree, or the branch/format is unrecognized. |

Only branch-named dpkg CLI/CGI/FPM/Apache runtime packages and Alpine PHP
runtime/CGI/FPM/Apache packages receive comparisons. Full vendor revisions
remain in the evidence; epochs and recognized packaging suffixes are separated
only for the upstream comparison. Extension and metapackage versions cannot
stand in for the runtime. Even a high vendor revision on an older upstream
base remains unverified, not automatically vulnerable or fixed.

Official-image declarations need an exact final version with recognized SAPI
and distribution tag suffixes. RC/beta/dev, custom suffixes, floating tags and
digest-only references remain unknown. Tag-plus-digest references are still
declarations: the digest is never resolved. Composer platform overrides do
not establish runtime versions. Different branches are assessed individually;
one fixed declaration cannot clear another older branch or a coverage gap.

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

An explicitly selected target root may be a symlink to a mounted snapshot.
Use the same root path for `--home` and `--exclude` paths beneath it. Links
discovered inside the selected root are still not followed. Keep the root
link and mounted contents stable throughout the scan.

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
package database status, per-record `upstreamAssessment`, `patchStatus`,
`presence`, and scoped coverage. Text
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

## Updating and verifying deployments

Use an appropriate fixed upstream release or a vendor-confirmed backport.
Restart serving workers or rebuild/redeploy containers as appropriate, then
verify each serving runtime has loaded the update. CLI or Composer results
cannot clear FPM, Apache, CGI or another web-serving runtime. Follow the
vendor's upgrade instructions and current PHP advisory.

Future snapshot updates must use primary advisories. Do not add a vendor
"fixed" verdict without verifying distribution identity, package provenance,
full version-ordering semantics and the vendor's exact fixed revision.

Tests must cover affected, fixed, backported and unresolved versions, plus
multiple PHP branches, stale declarations and incomplete coverage. Publish
accurate release notes and verify the actual release artifact before preparing
a placard or quote-post that claims the added coverage.

## October 23 session notice

CVE-2026-115560 is a separate, narrowly conditioned issue. The version table
above still covers only the two October 21 CVEs. See PHP's [notice](https://www.php.net/archive/2026.php). Keep
`session.upload_progress.enabled=0` where applicable until the regular fix;
the scanner does not determine runtime serializer changes or claim a fixed
version for the new issue.
