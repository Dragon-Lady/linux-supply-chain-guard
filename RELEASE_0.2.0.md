# v0.2.0

> **BREAKING CHANGES. Read before upgrading, especially in CI.**
>
> 1. **Exit code 3 now means "incomplete scan".** Any `--exclude DIR`, or a
>    directory that cannot be listed, makes the run exit 3 instead of 0 or 1.
>    CI jobs that treat every non-zero exit as failure, or that only expect
>    0/1/2/4, must be updated.
> 2. **Research and tool folders are no longer skipped by default.** Cache,
>    IDE/agent history, agent tool, cloud-sync and security-tool-named folders
>    are now scanned, so existing machines may report new findings.
>    `--include-research` is deprecated and has no effect.
> 3. **Sister-scanner checkouts can now exit 2.** Machines that keep sister-
>    scanner trees under the scan root may now report critical findings and
>    exit 2 (critical). Passing `--exclude` for those checkouts makes the run
>    incomplete and exit 3 instead (critical and token-monitor STOP still win
>    over 3 when they also apply).
> 4. **JSON shape changed.** `options.includeResearch` is replaced by
>    `options.excludePaths`. The report gains a `coverage` block and
>    `summary.incomplete`. Callers that read the old field must update.

GitHub release. Registry publication is separate.

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

- Candidate inspection failures, read failures, and discovery limits now mark
  aggregate coverage incomplete instead of reporting a clean scan. Coverage
  describes enabled rule lanes, not every byte or location on a host.
- Explicit scan roots must be existing directories; invalid roots exit 64.
- The package now includes the MIT license.

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
