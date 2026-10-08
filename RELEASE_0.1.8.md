# v0.1.8 (Unreleased)

Not yet released. No release date is set.

## Behavior changes

- **Exit code 3 means an incomplete scan.** It is returned when any directory
  was skipped because you passed `--exclude DIR`, or when a directory exists
  but could not be listed (for example permission denied). The JSON report
  sets `summary.incomplete: true` and describes the gap under `coverage`
  (`excludedPaths`, `skippedDirectories`, `unlistableDirectories`, and up to
  20 `unlistableSamples`).
  Precedence: token-monitor STOP (4) and critical (2) still win over 3;
  3 wins over review/warning (1) and clean (0).
- **Research and tool folders are no longer skipped by default.** Cache
  folders, IDE and agent history folders, agent tool folders, cloud-sync
  folders, and folders named after security tools are scanned like any other
  directory. The file walkers still skip dependency, VCS and build-output
  folders (`.git`, `.hg`, `.svn`, `node_modules`, `.venv`, `venv`, `dist`,
  `build`, `coverage`, `.next`), as before. Developer
  machines that hold checkouts of security tools may see more findings; skip
  those checkouts with `--exclude` (the scan is then reported incomplete).
- `--include-research` is deprecated. It is still accepted, prints a one-line
  warning to stderr, has no effect, and does not change the exit code.
- JSON report: new `coverage` block (`complete`, `excludedPaths`,
  `skippedDirectories`, `unlistableDirectories`, `unlistableSamples`) and
  `summary.incomplete`; `options.includeResearch`
  is replaced by `options.excludePaths`; `summary.suppressed.research` stays
  in the report and is always 0.

## Fixes

- A file planted under `~/.cache`, an agent or IDE history folder, a
  cloud-sync folder, or any folder named after a security tool was silently
  left out of the default scan and only counted as "suppressed research".
  Those folders are now scanned, so such indicators are reported.
- A directory the scanner could not list (for example a folder without read
  permission) was silently skipped and the run could still exit 0. It now
  marks the scan incomplete and exits 3, and the text report prints a
  `Coverage: INCOMPLETE` line naming the folders.
- Removed a hard-coded list of specific local folder paths from the scanner;
  directory skipping is now only what the operator asks for with `--exclude`.

## Using `--exclude` for deliberate mounts

For a deliberate cloud-sync mount or a tmpfs/in-memory mount under a home
directory, pass `--exclude /home/user/cloud-drive` (generic example path).
See the README section "Excluding deliberate mounts".
