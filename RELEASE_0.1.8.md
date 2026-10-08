# v0.1.8 (Unreleased)

Not yet released. No release date is set.

## Behavior changes

- **Exit code 3 means an incomplete scan.** It is returned when any directory
  was skipped because you passed `--exclude DIR`. The JSON report sets
  `summary.incomplete: true` and lists the skipped trees under `coverage`.
  Precedence: token-monitor STOP (4) and critical (2) still win over 3;
  3 wins over review/warning (1) and clean (0).
- **Nothing is skipped by default any more.** Cache folders, IDE and agent
  history folders, agent tool folders, cloud-sync folders, and folders named
  after security tools are scanned like any other directory. Developer
  machines that hold checkouts of security tools may see more findings; skip
  those checkouts with `--exclude` (the scan is then reported incomplete).
- `--include-research` is deprecated. It is still accepted, prints a one-line
  warning to stderr, has no effect, and does not change the exit code.
- JSON report: new `coverage` block (`complete`, `excludedPaths`,
  `skippedDirectories`) and `summary.incomplete`; `options.includeResearch`
  is replaced by `options.excludePaths`; `summary.suppressed.research` stays
  in the report and is always 0.

## Fixes

- A file planted under `~/.cache`, an agent or IDE history folder, a
  cloud-sync folder, or any folder named after a security tool was silently
  left out of the default scan and only counted as "suppressed research".
  Those folders are now scanned, so such indicators are reported.
- Removed a hard-coded list of specific local folder paths from the scanner;
  directory skipping is now only what the operator asks for with `--exclude`.

## Using `--exclude` for deliberate mounts

For a deliberate cloud-sync mount or a tmpfs/in-memory mount under a home
directory, pass `--exclude /home/user/cloud-drive` (generic example path).
See the README section "Excluding deliberate mounts".
