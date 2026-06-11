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
      "terminal-logger-utils": "1.0.0",
      "csc154-internall-depend": "^1.0.0",
      "@validate-sdk/v2": "^1.0.0",
      "google-cloud-secret-manager-config-poc": "^1.0.0"
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
  write(path.join(home, "ai-gateway", "requirements.txt"), "litellm==1.83.6\nstarlette==1.0.0\n");
  write(path.join(home, "ottercookie", "package.json"), JSON.stringify({
    dependencies: {
      "bjs-biginteger": "5.0.6",
      "bjs-lint-builder": "1.0.5"
    },
    scripts: {
      postinstall: "node test.js"
    }
  }));
  write(path.join(home, "ottercookie", "test.js"), [
    "const primary = 'https://cloudflareinsights.vercel.app/api/v1';",
    "const secondary = 'https://cloudflarefirewall.vercel.app/api/v1';",
    "const legacy = 'https://cloudflaresecurity.vercel.app/api/ssh-key';"
  ].join("\n"));
  write(path.join(home, "solana-fakefix", "package.json"), JSON.stringify({
    dependencies: {
      "@solana-labs/web3.js": "^2.0.0",
      "cms-storehub": "^1.0.0"
    },
    scripts: {
      postinstall: "node install.js"
    }
  }));
  write(path.join(home, "solana-fakefix", "requirements.txt"), "solana-web3-py==0.0.1\nspl-token-py\n");
  write(path.join(home, "solana-fakefix", "__init__.py"), [
    ".config/solana/id.json",
    ".solana/id.json",
    "wallet.json",
    "https://api.telegram.org/bot<redacted>/sendMessage",
    "http://104.239.66.223:8899",
    "http://77.90.185.225/v026a4a141fd9e7d2dd.js",
    "deno run -A",
    "conhost.exe --headless",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  ].join("\n"));
  const hadesBunSentinel = [".bun", "_ran"].join("");
  const hadesBunUrl = ["https://github.com/oven-sh/bun/releases/", "download/bun-v1.3.", "13/bun-linux-x64.zip"].join("");
  const hadesTitle = ["Hades - The End for the ", "Damned"].join("");
  const hadesWorkflowMarker = ["Run ", "Copilot\nformat", "-results\n"].join("");
  const hadesC2 = ["thebeautiful", "marchoftime"].join("");
  const hadesSshPath = ["/tmp/.sshu", "-setup.js"].join("");
  write(path.join(root, "tmp", hadesBunSentinel), "marker");
  write(path.join(home, "hades-env", "requirements.txt"), "langchain-core-mcp==1.4.2\n");
  write(
    path.join(home, "hades-env", ".venv", "lib", "python3.12", "site-packages", "langchain_core-setup.pth"),
    [
      "import os, sys, subprocess, urllib.request, tempfile",
      "for d in sys.path:",
      "    candidate = os.path.join(d, '_index.js')",
      `bun_url = '${hadesBunUrl}'`,
      "subprocess.run(['bun', 'run', candidate], check=False)",
      `open(os.path.join(tempfile.gettempdir(), '${hadesBunSentinel}'), 'w').close()`
    ].join("\n")
  );
  write(
    path.join(home, "hades-env", ".venv", "lib", "python3.12", "site-packages", "_index.js"),
    `${hadesTitle}\n${hadesWorkflowMarker}${hadesC2}\n${hadesSshPath}\n`
  );
  write(path.join(home, "hades-env", ".venv", "lib", "python3.12", "site-packages", "ensmallen_haswell.abi3.so"), "placeholder");
  write(path.join(home, "ai-gateway", "docker-compose.yml"), [
    "services:",
    "  litellm:",
    "    image: ghcr.io/berriai/litellm:main",
    "    command: litellm --host 0.0.0.0 --port 4000",
    "    environment:",
    "      - OPENAI_API_KEY=${OPENAI_API_KEY}",
    "    labels:",
    "      - route=/mcp-rest/test/connection",
    "      - route=/mcp-rest/test/tools/list",
    "      - trusted_hosts=*",
  ].join("\n"));

  const report = scanHost({ targetRoot: root, homePath: home });
  const ids = new Set(report.findings.map((finding) => finding.id));
  assert.strictEqual(report.summary.overall, "critical");
  assert(ids.has("alma-fragnesia-vulnerable-kernel"));
  assert(ids.has("fragnesia-risk-modules-loaded"));
  assert(ids.has("known-supply-chain-persistence-path"));
  assert(ids.has("transformers-pyz-present"));
  assert(ids.has("developer-secret-surfaces-present"));
  assert(ids.has("compromised-npm-package-reference"));
  assert(ids.has("ottercookie-npm-package-reference"));
  assert(ids.has("ottercookie-text-indicator"));
  assert(ids.has("solana-fakefix-npm-package-reference"));
  assert(ids.has("solana-fakefix-pypi-package-reference"));
  assert(ids.has("solana-fakefix-text-indicator"));
  assert(ids.has("dprk-npm-rat-package-reference"));
  assert(ids.has("dprk-npm-rat-text-indicator"));
  assert(ids.has("dynatrace-token-exposure"));
  assert(ids.has("dynatrace-teampcp-repo-term"));
  assert(ids.has("dynatrace-teampcp-service-term"));
  assert(ids.has("pcpjack-relay-artifact-path"));
  assert(ids.has("pcpjack-xsync-persistence-marker"));
  assert(ids.has("pcpjack-relay-file-name"));
  assert(ids.has("pcpjack-relay-text-indicator"));
  assert(ids.has("hades-runtime-artifact-path"));
  assert(ids.has("hades-pypi-package-version"));
  assert(ids.has("hades-pth-startup-hook-file"));
  assert(ids.has("hades-pth-bun-loader"));
  assert(ids.has("hades-syspath-payload-loader"));
  assert(ids.has("hades-python-payload-filename"));
  assert(ids.has("hades-text-indicator"));
  assert(ids.has("hades-known-native-extension"));
  assert(ids.has("litellm-cve-2026-42271-vulnerable-version"));
  assert(ids.has("litellm-starlette-host-header-chain"));
  assert(ids.has("litellm-public-bind"));
  assert(ids.has("litellm-mcp-test-route-reference"));
  assert(ids.has("litellm-provider-key-blast-radius"));
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
