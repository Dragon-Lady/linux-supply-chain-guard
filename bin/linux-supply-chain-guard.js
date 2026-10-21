#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scanHost } = require("../src/checker");

function writeNewReport(destination, report) {
  const data = `${JSON.stringify(report, null, 2)}\n`;
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(destination, flags, 0o600);
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("Report destination already exists; choose a new file.");
    throw error;
  }
  try { fs.writeFileSync(descriptor, data); }
  finally { fs.closeSync(descriptor); }
}

function printHelp() {
  console.log(`linux-supply-chain-guard

Read-only Linux host checker for supply-chain incident response.

Usage:
  linux-supply-chain-guard [target-root] [--json] [--report report.json] [--home /home/user]
                           [--include-historical] [--include-resolved] [--exclude DIR]...

Examples:
  linux-supply-chain-guard
  linux-supply-chain-guard / --json
  linux-supply-chain-guard /mnt/recovered-root --report report.json --home /mnt/recovered-root/home/alice

Default reports run the current/core rule lanes only. Use --include-historical
to run the older source-backed campaign catalog. Use --include-resolved to
include informational fixed/mitigated findings. Caches, IDE history, agent
folders and security-tool checkouts are scanned by default; the file walkers
only skip dependency, VCS and build-output folders (.git, .hg, .svn,
node_modules, .venv, venv, dist, build, coverage, .next). --exclude DIR
(repeatable) skips a directory tree you name; any excluded directory, and any
directory that exists but cannot be listed, marks the report incomplete.
PHP readiness is a dated, offline inventory check. Patch status stays unknown;
it does not run PHP, query containers, or verify deployed versions. PHP project
discovery also skips Composer vendor directories. See docs/php-readiness.md.
--include-research is deprecated: it is accepted, prints a warning to stderr,
and has no effect.
Exit codes: 0 no findings; 1 review/warning; 2 critical; 3 scan incomplete
(exclusions, unreadable inputs, failed candidate inspections, or resource limits);
4 token-monitor artifact (follow STOP guidance); 64 usage, target, or report error.
Precedence: 4 > 2 > 3 > 1 > 0.
`);
}

function parseArgs(argv) {
  const args = {
    targetRoot: "/",
    json: false,
    report: null,
    home: process.env.HOME || "",
    includeHistorical: false,
    includeResolved: false,
    excludePaths: [],
  };

  let targetSeen = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--report") {
      args.report = argv[i + 1];
      if (!args.report || args.report.startsWith("-")) throw new Error("--report requires a file path");
      i += 1;
    } else if (arg === "--home") {
      args.home = argv[i + 1] || "";
      if (!args.home || args.home.startsWith("-")) throw new Error("--home requires a directory path");
      i += 1;
    } else if (arg === "--include-historical") {
      args.includeHistorical = true;
    } else if (arg === "--include-research") {
      // Retained for compatibility: nothing is suppressed by default any more.
      if (!args.warnedIncludeResearch) {
        console.error("warning: --include-research is deprecated and has no effect; research folders are scanned by default");
        args.warnedIncludeResearch = true;
      }
    } else if (arg === "--exclude") {
      const value = argv[i + 1];
      if (!value || value.startsWith("-")) throw new Error("--exclude requires a directory path");
      args.excludePaths.push(value);
      i += 1;
    } else if (arg.startsWith("--exclude=")) {
      const value = arg.slice("--exclude=".length);
      if (!value) throw new Error("--exclude requires a directory path");
      args.excludePaths.push(value);
    } else if (arg === "--include-resolved") {
      args.includeResolved = true;
    } else if (!arg.startsWith("-")) {
      if (targetSeen) throw new Error("Only one target root may be specified");
      args.targetRoot = arg;
      targetSeen = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function formatText(report) {
  const lines = [];
  lines.push("linux-supply-chain-guard report");
  lines.push(`Target: ${report.targetRoot}`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push("");
  lines.push(`Overall: ${report.summary.overall}`);
  lines.push(
    `Findings: critical=${report.summary.critical}, warning=${report.summary.warning}, review=${report.summary.review}, info=${report.summary.info}`
  );
  const suppressed = report.summary.suppressed || {};
  lines.push(
    `Suppressed by default: resolved=${suppressed.resolved || 0}, duplicates=${suppressed.duplicates || 0}`
  );
  if (report.coverage && !report.coverage.complete) {
    lines.push("Coverage: INCOMPLETE - do not treat the absence of findings as a passed scan.");
    if (report.coverage.unreadablePaths) lines.push(`Unreadable inputs: ${report.coverage.unreadablePaths}`);
    if (report.coverage.limitedSearches) lines.push(`Discovery limits reached: ${report.coverage.limitedSearches}`);
    if (report.coverage.inspectionFailures?.length) lines.push(`Incomplete checks: ${report.coverage.inspectionFailures.join(", ")}`);
    const plural = (n) => `director${n === 1 ? "y" : "ies"}`;
    const skipped = report.coverage.skippedDirectories || 0;
    const unlistable = report.coverage.unlistableDirectories || 0;
    if (skipped > 0) {
      lines.push(
        `Coverage: INCOMPLETE - ${skipped} ${plural(skipped)} skipped by --exclude (${report.coverage.excludedPaths.join(", ")})`
      );
    }
    if (unlistable > 0) {
      lines.push(
        `Coverage: INCOMPLETE - ${unlistable} ${plural(unlistable)} could not be listed (${(report.coverage.unlistableSamples || []).join(", ")}${unlistable > (report.coverage.unlistableSamples || []).length ? ", ..." : ""})`
      );
    }
  }
  lines.push("");

  if (report.phpReadiness) {
    lines.push(`PHP readiness: ${report.phpReadiness.presence}; patch status UNKNOWN`);
    lines.push(`PHP advisory snapshot: ${report.phpReadiness.advisory.checkedOn}; recheck ${report.phpReadiness.advisory.primarySource}`);
    lines.push("PHP inventory is limited to configured paths; no matches is not proof PHP is absent.");
    lines.push("");
  }

  if (report.safeRemovalGuidance?.required) lines.push(report.safeRemovalGuidance.firstAction, "");

  for (const finding of report.findings) {
    lines.push(`[${finding.severity}] ${finding.id}`);
    lines.push(`  ${finding.title}`);
    if (finding.evidence) {
      lines.push(`  Evidence: ${finding.evidence}`);
    }
    lines.push(`  Guidance: ${finding.guidance}`);
    lines.push("");
  }

  return lines.join("\n");
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      printHelp();
      return;
    }

    const report = scanHost({
      targetRoot: args.targetRoot,
      homePath: args.home,
      includeHistorical: args.includeHistorical,
      includeResolved: args.includeResolved,
      excludePaths: args.excludePaths,
    });

    if (args.report) {
      writeNewReport(args.report, report);
    }

    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatText(report));
    }

    if (report.safeRemovalGuidance.sequenceSensitive) {
      process.exitCode = 4;
    } else if (report.summary.critical > 0) {
      process.exitCode = 2;
    } else if (report.summary.incomplete) {
      process.exitCode = 3;
    } else if (report.summary.warning > 0 || report.summary.review > 0) {
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`error: ${error.message}`);
    process.exitCode = 64;
  }
}

if (require.main === module) {
  main();
}
