"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanHost, compareKernelRelease } = require("../src/checker");

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function makeFixture() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "lscg-"));
}

function run() {
  assert.strictEqual(compareKernelRelease("5.14.0-611.54.3.el9_7", "5.14.0-611.54.4.el9_7"), -1);
  assert.strictEqual(compareKernelRelease("5.14.0-611.54.4.el9_7", "5.14.0-611.54.4.el9_7"), 0);
  assert.strictEqual(compareKernelRelease("5.14.0-611.55.1.el9_7", "5.14.0-611.54.4.el9_7"), 1);

  const root = makeFixture();
  const home = path.join(root, "home", "alice");
  write(path.join(root, "etc", "os-release"), 'ID="almalinux"\nVERSION_ID="9.7"\n');
  write(path.join(root, "proc", "sys", "kernel", "osrelease"), "5.14.0-611.54.3.el9_7\n");
  write(path.join(root, "proc", "modules"), "esp4 16384 0 - Live 0x0\nrxrpc 204800 0 - Live 0x0\n");
  write(path.join(root, "tmp", "transformers.pyz"), "payload");
  write(path.join(home, ".config", "systemd", "user", "gh-token-monitor.service"), "[Service]\n");
  write(path.join(home, ".config", "gh", "hosts.yml"), "github.com:\n");
  write(path.join(home, "repo", "package.json"), JSON.stringify({
    dependencies: {
      "terminal-logger-utils": "1.0.0"
    },
    scripts: {
      postinstall: "node utils.cjs"
    }
  }));
  const dynatraceFixtureToken = [
    "dt0c01",
    "ABCDEFGHIJKLMNOPQRSTUVWX",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL"
  ].join(".");
  write(path.join(home, "repo", "dynatrace-watch.md"), [
    "prod-dtappghrunner",
    "dynatrace.security.operations",
    dynatraceFixtureToken
  ].join("\n"));
  write(path.join(root, "var", "tmp", ".xs"), "chisel relay binary placeholder");
  write(path.join(root, "etc", "cron.d", "xsync"), "* * * * * root /var/tmp/.xs client R:0.0.0.0:2525:smtp.gmail.com:587 # xsync\n");
  write(path.join(root, "root", ".sliver-client", "configs", "root_localhost.cfg"), "Sliver localhost profile\n");
  write(path.join(root, "root", "excalibur", "smtp_proxies.csv"), "213.136.80.73,25,38.242.204.245\n");
  write(path.join(root, "root", "excalibur", "chisel_verifier.py"), "StrictHostKeyChecking=no\nchisel_verified.json\n");

  const report = scanHost({ targetRoot: root, homePath: home });
  const ids = new Set(report.findings.map((finding) => finding.id));
  assert.strictEqual(report.summary.overall, "critical");
  assert(ids.has("alma-fragnesia-vulnerable-kernel"));
  assert(ids.has("fragnesia-risk-modules-loaded"));
  assert(ids.has("known-supply-chain-persistence-path"));
  assert(ids.has("transformers-pyz-present"));
  assert(ids.has("developer-secret-surfaces-present"));
  assert(ids.has("dprk-npm-rat-package-reference"));
  assert(ids.has("dprk-npm-rat-text-indicator"));
  assert(ids.has("dynatrace-token-exposure"));
  assert(ids.has("dynatrace-teampcp-repo-term"));
  assert(ids.has("dynatrace-teampcp-service-term"));
  assert(ids.has("pcpjack-relay-artifact-path"));
  assert(ids.has("pcpjack-xsync-persistence-marker"));
  assert(ids.has("pcpjack-relay-file-name"));
  assert(ids.has("pcpjack-relay-text-indicator"));
  const tokenFinding = report.findings.find((finding) => finding.id === "dynatrace-token-exposure");
  assert(tokenFinding.evidence.includes("dt0c01.ABCDEFGHIJKLMNOPQRSTUVWX.<redacted>"));
  assert(!tokenFinding.evidence.includes("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"));

  const patched = makeFixture();
  write(path.join(patched, "etc", "os-release"), 'ID="almalinux"\nVERSION_ID="9.7"\n');
  write(path.join(patched, "proc", "sys", "kernel", "osrelease"), "5.14.0-611.54.4.el9_7\n");
  write(path.join(patched, "proc", "modules"), "\n");
  write(path.join(patched, "etc", "modprobe.d", "fragnesia.conf"), "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n");
  const patchedReport = scanHost({ targetRoot: patched, homePath: path.join(patched, "home", "alice") });
  assert(patchedReport.findings.some((finding) => finding.id === "alma-fragnesia-kernel-patched"));
  assert(!patchedReport.findings.some((finding) => finding.id === "fragnesia-risk-modules-loaded"));

  console.log("smoke tests passed");
}

run();
