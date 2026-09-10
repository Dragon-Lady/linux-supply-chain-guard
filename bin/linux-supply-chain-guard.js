#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scanHost } = require("../src/checker");

function printHelp() {
  console.log(`linux-supply-chain-guard

Read-only Linux host checker for supply-chain incident response.

Usage:
  linux-supply-chain-guard [target-root] [--json] [--report report.json] [--home /home/user]
                           [--include-historical] [--include-research] [--include-resolved]

Examples:
  linux-supply-chain-guard
  linux-supply-chain-guard / --json
  linux-supply-chain-guard /mnt/recovered-root --report report.json --home /mnt/recovered-root/home/alice

Default reports run the current/core rule lanes only. Use --include-historical
to run the older source-backed campaign catalog. Use --include-research to
include known scanner, test-fixture, IDE-history, and response-archive paths.
Use --include-resolved to include informational fixed/mitigated findings.
`);
}

function parseArgs(argv) {
  const args = {
    targetRoot: "/",
    json: false,
    report: null,
    home: process.env.HOME || "",
    includeHistorical: false,
    includeResearch: false,
    includeResolved: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--report") {
      args.report = argv[i + 1];
      i += 1;
    } else if (arg === "--home") {
      args.home = argv[i + 1] || "";
      i += 1;
    } else if (arg === "--include-historical") {
      args.includeHistorical = true;
    } else if (arg === "--include-research") {
      args.includeResearch = true;
    } else if (arg === "--include-resolved") {
      args.includeResolved = true;
    } else if (!arg.startsWith("-")) {
      args.targetRoot = arg;
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
    `Suppressed by default: research=${suppressed.research || 0}, resolved=${suppressed.resolved || 0}, duplicates=${suppressed.duplicates || 0}`
  );
  lines.push("");

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
      includeResearch: args.includeResearch,
      includeResolved: args.includeResolved,
    });

    if (args.report) {
      fs.writeFileSync(args.report, `${JSON.stringify(report, null, 2)}\n`);
    }

    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatText(report));
    }

    if (report.summary.critical > 0) {
      process.exitCode = 2;
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
