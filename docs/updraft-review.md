# UpdraftCentral incident review

This optional, offline check supports investigation of the October 2026
UpdraftCentral Cloud key compromise. It reads selected files and never starts
PHP, WordPress, WP-CLI, a database client or a network request. It does not
revoke keys, remove plugins, change accounts or patch a site.

```sh
linux-supply-chain-guard /mnt/site-snapshot \
  --wordpress-root /mnt/site-snapshot/var/www/site \
  --updraft-log /mnt/site-snapshot/evidence/access.log \
  --wordpress-evidence /mnt/site-snapshot/evidence/wordpress.json \
  --json --report ./private-incident-report.json
```

Each option can be used independently. WordPress roots and logs are repeatable;
one evidence file is accepted. Paths refer to the inspecting machine and must
be inside the target root, including its mount prefix. Use a stable read-only
snapshot. Reports should remain private and outside the selected site.

## Evidence and limits

| Input | Checked | Interpretation |
| --- | --- | --- |
| `--wordpress-root DIR` | PHP, PHP-numbered, PHTML and INC files recursively under `wp-content/plugins`, `mu-plugins`, and `upgrade` | Published text/code combinations and generic login/hiding patterns prompt review, including unpacked plugins whose installation may have failed. No dependency or hidden-directory exclusions. |
| `--updraft-log FILE` | Explicit UTF-8 text, including exported UpdraftCentral events or access logs | Probe marker, plugin upload/delete commands, shortened client identifier and trigger-shaped query parameters are separate findings. Events may be authorized, spoofed or rejected; they do not prove execution. |
| `--wordpress-evidence FILE` | Strict sanitized JSON, described below | Cloud/unclassified key counts, non-admin accounts with elevated capabilities, and option-name suffixes prompt review. No key values or account credentials are accepted. |

Log trigger checks retain the underscore-prefixed 4–10 alphanumeric parameter
shape documented by Patchstack and also match Nethemba's 12 lowercase hexadecimal
parameter without an underscore. Both require a 32-character value bounded by
query/log delimiters. A working variant can reuse an existing administrator,
so database evidence is not required for the log finding.

The report includes `updraftReview.layers` and always reports
`compromiseStatus: "unknown"`. `coverage.complete` means only that the selected
inputs were inspected within supported limits. Omitted layers are
`not-selected`, never silently treated as checked. Absence of matches is not
proof of safety. Legitimate plugins and customized roles can match these
heuristics. A plugin's display name alone is not used as a detection rule.

Only conventional `wp-content` paths are inspected; custom content locations,
themes, uploads and files outside those three trees are not inspected by this
lane. It does not evaluate `wp-config.php` to discover overrides. Obfuscation,
different extensions and new variants may evade static markers. The separate
`--webroot` / `--web-baseline` workflow can compare broader file changes with a
trusted baseline. A snapshot taken after compromise is not a clean baseline.

The shared descriptor-anchored reader preserves the v0.4.1 procfs checks.
Symlinks, special files, missing selected inputs, unreadable/changing files,
invalid UTF-8/JSON and exhausted limits produce incomplete coverage and CLI
exit 3 unless a higher-priority finding applies. Empty logs are incomplete.
Missing optional `mu-plugins`/`upgrade` directories are allowed; the site,
`wp-content` and `plugins` directories must exist. Limits per lane: 8 MiB per
file, 128 MiB total, 10,000 reads, 50,000 entries, depth 32, 2,000 findings,
and a cooperative 10-second budget. No compressed-log decompression occurs.

Findings contain paths, fixed descriptions and numeric user IDs, not log
lines, query tokens, addresses, usernames, email addresses or option values.
Paths and IDs still reveal deployment information; keep reports private.

## Sanitized database evidence

Prepare this projection from a trusted database snapshot using trusted tools.
Do not bootstrap the suspected site's PHP or run its plugins to generate it.
This checker provides no live database exporter. A database administrator must
map the fields below; verify completeness, site/table prefix and provenance.
For multisite, use a separate export for each site's roles/capabilities.

```json
{
  "schema": 1,
  "keys": {"cloud": 0, "selfHosted": 0, "unknown": 0},
  "users": [
    {"id": 17, "roles": ["editor"], "capabilities": ["edit_posts"]}
  ],
  "optionNames": []
}
```

All fields are required; unknown fields are rejected. `keys` counts remaining
UpdraftCentral connections by independently verified dashboard provenance;
classify uncertainty as `unknown`. Do not include public/private key bytes.
`users` lists unique positive IDs, role names and **effective enabled**
capability names, combining role and per-user grants while honoring explicit
denials. A stored false value is not a granted capability. Include all accounts,
not only administrators. `optionNames` contains unique names only, never values.
SQL dumps, serialized PHP and arbitrary WP-CLI exports are not supported.

Schema 1 does not represent UpdraftPlus Migrator key counts or stored account
passwords. An `updraft_migrator_localkeys` option name alone cannot establish
whether keys remain active; inspect those separately using trusted tools and
the researcher guidance. Never add credentials or key values to this export.

The checker cannot verify that an export includes every key/account/option or
that it matches the selected files and logs. Zero exported keys is not proof
that stolen keys were never used. Self-hosted-only keys do not trigger the
cloud-key finding. Custom roles legitimately granting elevated capabilities
may need review; the scanner does not decide whether they are authorized.

## Advisory snapshot and operator follow-up

Sources checked October 23, 2026:

- [TeamUpdraft incident notice](https://teamupdraft.com/blog/security-incident-october-2026/)
- [Patchstack investigation](https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/)
- [Nethemba investigation and updated variants](https://nethemba.com/updraftcentral-backdoor-analysis/)

The vendor names 1.26.13 (free) / 2.26.13 (Premium) as its revocation release.
Nethemba reports that its cutoff leaves some incident-period keys intact.
Check remaining connections directly; an installed version does not establish
revocation, and an update does not remove an existing backdoor. Self-hosted
UpdraftCentral was not affected by the vendor breach according to TeamUpdraft.

TeamUpdraft's October 21 update asks Premium users to inspect sites even if
they never knowingly used UpdraftCentral. Nethemba reports that logging into
an account inside the plugin can create a key through a default-selected
connection option; installing the plugin alone does not create one. Its
October 21 observations include further command attempts after the revocation
release, reinforcing the need to verify remaining keys directly.

From a trusted administrative environment, preserve evidence, revoke affected
site connections, inspect plugins and effective account privileges, and follow
the linked recovery guidance. Credential rotation belongs on a clean system.
This incident is separate from the PHP core advance security notice and does
not change PHP readiness's unknown patch status.
