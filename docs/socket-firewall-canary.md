# Socket Firewall Canary

Socket Firewall can be tested as an opt-in install wrapper before making it a
default developer or CI path. Keep this canary reversible: do not replace normal
`npm install` workflows until the wrapper is observed on a disposable runner.

## Setup

Install the wrapper on a canary host or temporary CI runner:

```bash
npm install -g sfw
```

Do not install it globally on production build hosts until the canary has clean
results and a rollback path.

## Canary Command

From this repository:

```bash
npm run canary:socket-firewall
```

For timestamped local logs:

```bash
npm run canary:socket-firewall:log
```

The package script runs:

```bash
sfw npm install --package-lock-only --ignore-scripts --audit=false --fund=false
```

This keeps the first canary focused on dependency resolution and Socket
Firewall interception while preventing npm lifecycle scripts from executing.

## Age Gate

As of 2026-05-14, `npm view sfw version time --json` reports latest version
`2.0.4`, published `2025-09-30T18:01:24.292Z`. That npm wrapper package is
well outside the 7-day package-age gate.

The age gate does not make `sfw` trusted by default. Because this package is now
part of the defensive path and could itself become a target, continue to monitor
the npm wrapper package, its publisher activity, and any Socket Firewall binary
downloaded by the wrapper during first run.

## Canary Duration

Keep Socket Firewall in canary for at least 7 full days before promoting it to a
default developer or CI install path.

Run the canary no more than once every 6 hours during that window. This gives
four observation points per day while keeping it much quieter than active
Rocky/Oracle 5-minute monitoring.

Current Windows timer:

```powershell
LinuxSupplyChainGuard-SocketFirewallCanary
```

It runs `scripts/run-socket-firewall-canary.ps1`, writes timestamped logs under
`logs/socket-firewall-canary/`, repeats every 6 hours, and stops after 7 days.

Inspection commands:

```powershell
Get-ScheduledTaskInfo -TaskName 'LinuxSupplyChainGuard-SocketFirewallCanary'
(Get-ScheduledTask -TaskName 'LinuxSupplyChainGuard-SocketFirewallCanary').Triggers[0].Repetition
```

Reset the 7-day canary clock if any of these change:

- The published `sfw` npm package version.
- The downloaded Socket Firewall binary version.
- The binary source URL or checksum.
- The package's publisher or maintainer set.
- The wrapper behavior, cache layout, or update behavior.

Under normal conditions, an npm package already outside the 7-day age gate could
move from staging to execution after local tests. During an active supply-chain
malware campaign, keep the extra 7-day operational canary even when the npm
package age gate has passed.

## Pass Criteria

- `sfw` starts and delegates to npm without breaking the install flow.
- No unexpected `package.json` changes occur.
- Any generated or updated lockfile change is reviewed before commit.
- The wrapper emits useful allow/block output for maintainer review.
- The fetched Socket Firewall binary version and source are captured in canary
  logs before promotion.

## Ongoing Protocol

- Keep normal safe package protocols active after the canary passes.
- Treat packages introduced through `sfw` the same as packages introduced
  through direct npm installs until the active malware campaign is contained.
- Continue package-age checks, lockfile review, script suppression on first
  contact, and canary-only execution for newly introduced tooling.
- Do not let Socket Firewall replace containment, evidence preservation,
  credential rotation from a clean host, or rebuild/reimage decisions when host
  compromise is plausible.

## Rollback

Use the regular npm command path:

```bash
npm install --package-lock-only --ignore-scripts --audit=false --fund=false
```

If the canary causes install failures unrelated to a real package block, remove
the wrapper from the canary runner and keep normal installs unchanged.
