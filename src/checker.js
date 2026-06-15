"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PATCHED_KERNELS = {
  "8": "4.18.0-553.124.2.el8_10",
  "9": "5.14.0-611.54.4.el9_7",
  "10": "6.12.0-124.56.2.el10_1",
};

const KNOWN_HASHES = new Set([
  "5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b",
]);

const OPENCLAW_FIXED = "2026.4.23";
const OPENCLAW_CONFIG_FILES = new Set([".crabbox.yaml", ".crabbox.yml"]);
const NPM_V12_PREPARE_MIN = "11.16.0";

const KNOWN_DPRK_NPM_PACKAGES = [
  "terminal-logger-utils",
  "pretty-logger-utils",
  "ts-logger-pack",
  "pinno-loggers",
];

const KNOWN_COMPROMISED_NPM_PACKAGES = [
  "atomic-lockfile",
  "csc154-internall-depend",
  "ecto-flag-read",
  "@validate-sdk/v2",
  "google-cloud-secret-manager-config-poc",
];

const ATOMIC_ARCH_AUR_PACKAGE = "atomic-lockfile";

const OTTERCOOKIE_NPM_PACKAGES = [
  "bjs-lint-builders", // push-guard: ignore
  "bjs-lint-builder", // push-guard: ignore
  "bjs-biginteger", // push-guard: ignore
  "hjs-lint-builders", // push-guard: ignore
  "sjs-builders", // push-guard: ignore
  "sjs-builder", // push-guard: ignore
  "npm-doc-builder", // push-guard: ignore
];

const OTTERCOOKIE_TEXT_INDICATORS = [
  "cloudflareinsights.vercel.app", // push-guard: ignore
  "cloudflarefirewall.vercel.app", // push-guard: ignore
  "cloudflaresecurity.vercel.app", // push-guard: ignore
  "cloudflareinsights[.]vercel[.]app", // push-guard: ignore
  "cloudflarefirewall[.]vercel[.]app", // push-guard: ignore
  "cloudflaresecurity[.]vercel[.]app", // push-guard: ignore
  "node test.js",
  "postinstall",
];

const SOLANA_FAKEFIX_NPM_PACKAGES = [
  "@solana-labs/ancor",
  "@solana-labs/etherjs",
  "@solana-labs/spl-toke",
  "@solana-labs/web3-js",
  "@solana-labs/web3.js",
  "@solana-labs/web3js",
  "cms-github",
  "cms-helpgit",
  "cms-storehub",
  "shopifyto-cms",
  "solana-js-client",
  "solana-mev-bot",
  "solana-rpc-client",
  "solana-web3-community",
  "solana-web3-fixed",
  "solana-web3-fork",
  "solana-web3-lts",
  "solana-web3-patched",
  "solana-web3-stable",
  "solana-web3-v1",
  "to-cms",
];

const SOLANA_FAKEFIX_PYPI_PACKAGES = [
  "solana-cli-py",
  "solana-web3",
  "solana-web3-py",
  "spl-token-py",
];

const SOLANA_FAKEFIX_TEXT_INDICATORS = [
  ".config/solana/id.json",
  ".solana/id.json",
  "wallet.json",
  "keypair.json",
  "api.telegram.org/bot",
  "104.239.66.223:8899",
  "77.90.185.225",
  "raw.githubusercontent.com/PassWord1337/updates/main/install.js",
  "Deno.Command",
  "deno run -A",
  "conhost.exe --headless",
  "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "127.0.0.1:10092",
  "ChromeSetup.exe",
  "aCpsuydgwbasd.exe",
];

const HADES_PYPI_PACKAGES = {
  bramin: ["0.0.2", "0.0.3", "0.0.4"],
  cmd2func: ["0.2.2", "0.2.3"],
  coolbox: ["0.4.1", "0.4.2"],
  dreamgen: ["1.8.1"],
  "dynamo-release": ["1.5.4"],
  embiggen: ["0.11.97"],
  ensmallen: ["0.8.101"],
  "executor-engine": ["0.3.4", "0.3.5"],
  "executor-http": ["0.1.3", "0.1.4"],
  funcdesc: ["0.2.2", "0.2.3"],
  gpsea: ["0.9.14"],
  "instructor-mcp": ["1.15.2", "1.15.3"],
  "langchain-core-mcp": ["1.4.2", "1.4.3"],
  magique: ["0.6.8", "0.6.9"],
  "magique-ai": ["0.4.4", "0.4.5"],
  mem8: ["6.0.1"],
  "mflux-streamlit": ["0.0.3", "0.0.4"],
  mrbios: ["0.1.1", "0.1.2"],
  "napari-ufish": ["0.0.2", "0.0.3"],
  nucbox: ["0.1.2", "0.1.3"],
  okite: ["0.0.7", "0.0.8"],
  "openai-mcp": ["2.41.1", "2.41.2"],
  "orchestr8-platform": ["3.3.2"],
  "pantheon-agents": ["0.6.1", "0.6.2"],
  "pantheon-toolsets": ["0.5.5", "0.5.6"],
  "phenopacket-store-toolkit": ["0.1.7"],
  ppkt2synergy: ["0.1.1"],
  pyphetools: ["0.9.120"],
  "ray-mcp-server": ["0.2.1"],
  rlask: ["3.1.7"],
  rsquests: ["2.34.3"],
  "spateo-release": ["1.1.2"],
  synago: ["0.1.1", "0.1.2"],
  "tiktoken-mcp": ["0.13.1", "0.13.2"],
  tlask: ["3.1.4"],
  ufish: ["0.1.2", "0.1.3"],
  uprobe: ["0.1.3", "0.1.4"],
};

const HADES_TEXT_INDICATORS = [
  joinParts("Hades - The End for the ", "Damned"),
  joinParts("IfYouYankThisToken", "ItWillNukeTheComputerOfTheOwnerFully"),
  joinParts("results/results-", "*.json"),
  joinParts("format", "-results"),
  joinParts("Run ", "Copilot"),
  joinParts(".bun", "_ran"),
  joinParts("bun-v1.3.", "13"),
  joinParts("bun-v1.3.", "14"),
  joinParts("oven-sh/bun/releases/", "download"),
  "urllib.request",
  "urlretrieve",
  "tempfile.gettempdir",
  "subprocess.run",
  "langchain_core-setup.pth",
  joinParts("thebeautiful", "marchoftime"),
  joinParts("thebeautiful", "snadsoftime"),
  joinParts("/tmp/.sshu", "-setup.js"),
  "/var/run/docker.sock",
  "harden-runner",
];

const HADES_NATIVE_EXTENSION_FILES = new Set([
  "ensmallen_haswell.abi3.so",
  "ensmallen_core2.abi3.so",
]);

const DPRK_NPM_TEXT_INDICATORS = [
  "utils.cjs",
  "/api/validate/keyboard-events",
  "pwdKeyString",
  "Telegram Desktop",
];

const DYNATRACE_TOKEN_PATTERN = /dt0[cs][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64,}/gi;

const DYNATRACE_TEAMPCP_REPO_TERMS = [
  "hard-copilot",
  "hard-csc",
  "hard-iam",
  "local-cluster-setup",
  "nonprod-dtappghrunner",
  "prod-copilot",
  "prod-csc",
  "prod-dtappghrunner",
  "prod-iam",
];

const DYNATRACE_TEAMPCP_SERVICE_TERMS = [
  "dynatrace.scorecards",
  "dynatrace.security.enrichment",
  "dynatrace.security.operations",
  "dynatrace.security.threats.exploits",
  "dynatrace.sensitive.data.center",
  "dynatrace.services",
  "dynatrace.snowflake.connector",
  "dynatrace.software.lifecycle",
  "dynatrace.specktrack",
  "dynatrace.storage.management",
];

const PCPJACK_TEXT_INDICATORS = [
  "PCPJack",
  "chisel_verifier.py",
  "chisel_verified.json",
  "smtp_proxies.csv",
  "smtp.gmail.com:587",
  "38.242.204.245",
  "38.242.204[.]245",
  "213.136.80.73",
  "213.136.80[.]73",
  "/root/.sliver-client/configs/root_localhost.cfg",
  "/root/excalibur/smtp_proxies.csv",
  "StrictHostKeyChecking=no",
  "R:0.0.0.0:",
  "R:.*:",
  "socks5",
];

const PCPJACK_FILE_NAMES = new Set([
  "chisel_verifier.py",
  "chisel_verified.json",
  "smtp_proxies.csv",
  "root_localhost.cfg",
  "sliver-client.cfg",
]);

const PEOPLESOFT_MESH_AGENT_FILES = new Set([
  "meshagent32-azure-ops.exe",
  "meshagent64-azure-ops.exe",
  "meshagent64-v2.exe",
]);

const PEOPLESOFT_EXTORTION_MARKER = "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT";

const PEOPLESOFT_CAMPAIGN_NETWORK_INDICATORS = [
  "azurenetfiles.net",
  "wss://azurenetfiles.net:443/agent.ashx",
  "142.11.200.186",
  "142.11.200.187",
  "142.11.200.188",
  "142.11.200.189",
  "142.11.200.190",
  "176.120.22.24",
];

const GENTLEMEN_KNOWN_HASHES = new Map([
  ["22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67", "Gentlemen ransomware encryptor"],
  ["078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b", "PsExec binary embedded/dropped by Gentlemen ransomware"],
  ["fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68", "Gentlemen ransomware wallpaper bitmap"],
]);

const GENTLEMEN_TOOLKIT_FILES = new Set([
  "dControl.exe",
  "ConfigureDefender.exe",
  "PCHunter64_new.exe",
  "PowerRun_x64.exe",
  "PowerTool64_new.exe",
  "netscan.exe",
  "WinDefGpo_Reg.ps1",
  "def1.bat",
  "z.bat",
  "z1.bat",
  "clearlog.bat",
  "enable_dump_pass.reg",
  "VmManagedSetup.exe",
  "5541.exe",
  "ngrok.exe",
  "rustdesk.exe",
]);

const GENTLEMEN_NETWORK_INDICATORS = [
  "176.120.22.127",
  "176.120.22[.]127",
  "2gkRUQNkJyaGkvuDziSq1RGIrwl_4bGyJtv6ez2Hk8Hrd5zvq",
  "2ozoAve91tpILCwKCbRDNz7us8e_2qLk1aLKZoV4Y6TfrcfjK",
];

const LITELLM_AFFECTED_MIN = "1.74.2";
const LITELLM_FIXED = "1.83.7";
const STARLETTE_FIXED = "1.0.1";
const LITELLM_MCP_TEST_ROUTES = [
  "/mcp-rest/test/connection",
  "/mcp-rest/test/tools/list",
];
const LITELLM_CONFIG_TERMS = [
  "litellm",
  "LiteLLM",
  "LITELLM",
  "mcp-rest",
];
const AGENTJACKING_SENTRY_TERMS = [
  "sentry",
  "Sentry",
  "SENTRY_DSN",
  "sentry_dsn",
  "ingest.sentry.io",
];
const AGENTJACKING_MCP_TERMS = [
  "mcp",
  "MCP",
  "Model Context Protocol",
];

const OPERATION_HIGHLAND_SHA1_HASHES = loadHashSet("operation-highland-sha1.json");
const OPERATION_HIGHLAND_IOC_PATHS = [
  "/usr/share/man9/ph/.ph.man",
  "/usr/share/man9/ph",
  "/lib/systemd/system/chrom.service",
  "/etc/init.d/chrom",
  "/usr/bin/mlx",
  "/usr/bin/pnscan",
  "/usr/bin/stats",
  "/usr/bin/vlra",
  "/usr/lib/eth-scsi/libethscsi.so",
  "/usr/lib/psliba.so.7",
  "/usr/lib/psliba.so.7b",
  "/usr/lib/sslsh.ko",
  "/usr/sbin/.ssh.log",
  "/usr/sbin/auditdb",
  "/usr/sbin/land",
  "/usr/sbin/pnscan",
  "/usr/sbin/pscan",
  "/usr/share/nginx/cgi/cgi-bin/uptime",
  "/var/lib/sam",
];

const OPERATION_HIGHLAND_LOWER_CONFIDENCE_PATHS = new Set([
  "/usr/bin/mlx",
  "/usr/bin/pnscan",
  "/usr/bin/stats",
  "/usr/bin/vlra",
  "/usr/sbin/land",
  "/usr/sbin/pnscan",
  "/usr/sbin/pscan",
]);

const OPERATION_HIGHLAND_AUTH_FILES = [
  "/usr/bin/scp",
  "/usr/bin/sftp",
  "/usr/bin/ssh",
  "/usr/bin/ssh-keygen",
  "/usr/lib/security/pam_unix.so",
  "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
  "/usr/sbin/sshd",
  "/lib/security/pam_unix.so",
  "/lib/x86_64-linux-gnu/security/pam_unix.so",
];

const OPERATION_HIGHLAND_FILE_NAMES = new Set([
  ".ph.man",
  ".ssh.log",
  "auditdb",
  "chrom.service",
  "cln",
  "collect.sh",
  "land",
  "mlx",
  "p.sh",
  "pnscan",
  "pscan",
  "psliba.so.7",
  "psliba.so.7b",
  "sslsh.ko",
  "stats",
  "uudecode.pl",
  "uuencode.sh",
  "vlra",
]);

const OPERATION_HIGHLAND_NETWORK_INDICATORS = [
  "gs.thc.org",
  "gs.thc[.]org",
  "mobi.urgpt.dev",
  "mobi.urgpt[.]dev",
  "135.125.107.221",
  "135.125.107[.]221",
  "15.197.240.20",
  "15.197.240[.]20",
  "172.233.218.87",
  "172.233.218[.]87",
  "192.145.44.201",
  "192.145.44[.]201",
  "23.239.3.135",
  "23.239.3[.]135",
];

const OPERATION_HIGHLAND_TEXT_INDICATORS = [
  "Pamauth@123456",
  "/usr/share/man9/ph/.ph.man",
  "/usr/share/man9/ph/",
  "/usr/sbin/.ssh.log",
  "/usr/lib/eth-scsi/libethscsi.so",
  "/var/lib/sam",
  "/usr/sbin/auditdb",
  "/usr/share/nginx/cgi/cgi-bin/uptime",
  "fcgiwrap",
  "fastcgi_pass",
];

const OPERATION_HIGHLAND_PROCESS_MASQUERADE = [
  "[khubd]",
  "[kauditd] -sh",
  "smbd -D",
];

const PROVIDER_KEY_ENV_TERMS = [
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "AZURE_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "AWS_ACCESS_KEY_ID",
  "GOOGLE_API_KEY",
  "GEMINI_API_KEY",
  "MISTRAL_API_KEY",
  "COHERE_API_KEY",
];

const DEPENDENCY_FILE_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

const WATCH_FILE_NAMES = new Set([
  ...DEPENDENCY_FILE_NAMES,
  "requirements.txt",
  "pyproject.toml",
  "poetry.lock",
  "Pipfile",
  "Pipfile.lock",
  "uv.lock",
  "Dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  ".npmrc",
  ".pypirc",
  ".SRCINFO",
  "PKGBUILD",
  "README.md",
  "SECURITY.md",
  ".gitignore",
  PEOPLESOFT_EXTORTION_MARKER,
  "psappsrv.cfg",
  "config.xml",
  ...PEOPLESOFT_MESH_AGENT_FILES,
  "gentlemen.bmp",
  "README-GENTLEMEN.txt",
  "psexec.exe",
  ...GENTLEMEN_TOOLKIT_FILES,
  ...OPERATION_HIGHLAND_FILE_NAMES,
]);

const WATCH_FILE_EXTENSIONS = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".lock",
  ".md",
  ".py",
  ".pth",
  ".so",
  ".csv",
  ".txt",
  ".cfg",
  ".xml",
  ".log",
  ".jsp",
  ".bat",
  ".ps1",
  ".reg",
  ".cmd",
  ".bmp",
  ".env",
  ".tf",
]);

const ASTRO_GITIGNORE_HIDE_FILES = [
  "branch_structure.json",
  "temp_auto_push.bat",
  "temp_interactive_push.bat",
];

function scanHost(options = {}) {
  const targetRoot = path.resolve(options.targetRoot || "/");
  const homePath = options.homePath || process.env.HOME || "";
  const findings = [];
  const osRelease = readOsRelease(readText(mapLinuxPath(targetRoot, "/etc/os-release")));
  const kernelRelease =
    options.kernelRelease ||
    readText(mapLinuxPath(targetRoot, "/proc/sys/kernel/osrelease")).trim();

  checkPlatform(findings, osRelease, kernelRelease);
  checkAlmaFragnesia(findings, osRelease, kernelRelease);
  checkKernelModules(findings, targetRoot);
  checkPersistence(findings, targetRoot, homePath);
  checkCompromisedNpmPackages(findings, targetRoot, homePath);
  checkAtomicArchAurCompromise(findings, targetRoot, homePath);
  checkDprkNpmRat(findings, targetRoot, homePath);
  checkOtterCookieNpm(findings, targetRoot, homePath);
  checkSolanaFakeFix(findings, targetRoot, homePath);
  checkAstroConfigC2(findings, targetRoot, homePath);
  checkHadesPyPi(findings, targetRoot, homePath);
  checkDynatraceTeamPcpWatch(findings, targetRoot, homePath);
  checkPcpJackRelayArtifacts(findings, targetRoot, homePath);
  checkGentlemenRansomware(findings, targetRoot, homePath);
  checkPeopleSoftCve202635273(findings, targetRoot, homePath);
  checkLiteLlmGatewayExposure(findings, targetRoot, homePath);
  checkOpenClawAgentExposure(findings, targetRoot, homePath);
  checkAgentjackingSentryMcpExposure(findings, targetRoot, homePath);
  checkNpmV12Readiness(findings, targetRoot, homePath);
  checkOperationHighlandAuthStack(findings, targetRoot, homePath);
  checkTransformersPayload(findings, targetRoot);
  checkSecretSurfaces(findings, targetRoot, homePath);

  return {
    tool: "linux-supply-chain-guard",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    targetRoot,
    host: {
      os: osRelease,
      kernelRelease,
    },
    summary: summarize(findings),
    findings,
  };
}

function checkAstroConfigC2(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (isAstroConfigFileName(base)) {
      const hasCreateRequire = /\bcreateRequire\s*\(/i.test(text);
      const hasEvalSink = /\b(eval|Function)\s*\(/i.test(text);
      const hasNetworkLoader = /\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)|\bfrom\s+['"](?:node:)?https?['"]|\bhttps?\s*\.\s*(?:request|get)\s*\(|\bfetch\s*\(/i.test(text);
      const hasGlobalMutation = /global\s*(?:\.|\[)/i.test(text);
      const hasBlockchainRelay = /trongrid|aptoslabs|bsc-dataseed|publicnode|eth_getTransactionByHash|Sec-V|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP/i.test(text);
      const hasHiddenExecutableLine = text
        .split(/\r?\n/)
        .some((line) => line.length > 300 && /[ \t]{80,}\S/.test(line) && astroConfigLineHasLoaderSignal(line));

      if (hasCreateRequire && (hasEvalSink || hasNetworkLoader || hasGlobalMutation || hasBlockchainRelay)) {
        addFinding(findings, "critical", "astro-config-require-loader", "Astro config reconstructs require and also contains executable loader behavior.", relative, "Do not run astro dev/build/preview in this tree until the config diff and branch provenance are reviewed.");
      }
      if (hasNetworkLoader && hasEvalSink) {
        addFinding(findings, "critical", "astro-config-network-eval-loader", "Astro config combines network retrieval with eval/function execution behavior.", relative, "Treat any prior Astro build/dev/preview from this tree as potential payload execution and rotate exposed developer credentials from a clean posture.");
      }
      if (hasBlockchainRelay) {
        addFinding(findings, "warning", "astro-config-blockchain-c2-marker", "Astro config references blockchain/C2 relay markers reported in config-as-code supply-chain attacks.", relative, "Correlate with branch history, outbound network logs, and build/dev server execution.");
      }
      if (hasHiddenExecutableLine) {
        addFinding(findings, "warning", "astro-config-hidden-payload-line", "Astro config contains a long horizontally hidden executable-looking payload line.", relative, "Review the full line with wrapping disabled before running Astro commands.");
      }
    }

    if (base === ".gitignore") {
      for (const artifact of ASTRO_GITIGNORE_HIDE_FILES) {
        if (text.includes(artifact)) {
          addFinding(findings, "warning", "gitignore-hidden-pr-tooling", ".gitignore hides PR automation/helper artifact names reported with Astro config C2 injection.", `${relative}: ${artifact}`, "Review branch provenance and local ignored files before building or opening this repo in an agent.");
        }
      }
    }
  }
}

function checkPlatform(findings, osRelease, kernelRelease) {
  if (!osRelease.ID && !kernelRelease) {
    addFinding(findings, "review", "platform-not-linux-root", "Linux host metadata was not found.", "", "Run this tool on a Linux host root or mounted Linux filesystem.");
  }
}

function checkAlmaFragnesia(findings, osRelease, kernelRelease) {
  const distroId = String(osRelease.ID || "").toLowerCase();
  if (distroId !== "almalinux") {
    return;
  }

  const major = String(osRelease.VERSION_ID || "").split(".")[0];
  const patched = PATCHED_KERNELS[major];
  if (!patched) {
    addFinding(findings, "review", "alma-fragnesia-unknown-release", "AlmaLinux release is not in the built-in Fragnesia matrix.", `VERSION_ID=${osRelease.VERSION_ID || "unknown"}`, "Check vendor advisories for CVE-2026-46300 patched kernel guidance.");
    return;
  }

  if (!kernelRelease) {
    addFinding(findings, "review", "alma-fragnesia-kernel-unknown", "AlmaLinux host found but kernel release could not be read.", "", `Confirm the running kernel is ${patched} or newer for AlmaLinux ${major}.`);
    return;
  }

  if (compareKernelRelease(kernelRelease, patched) < 0) {
    addFinding(findings, "critical", "alma-fragnesia-vulnerable-kernel", "AlmaLinux kernel appears older than the Fragnesia patched kernel.", `${kernelRelease} < ${patched}`, "Patch the kernel and reboot, or apply vendor-approved temporary module mitigations until reboot is possible.");
  } else {
    addFinding(findings, "info", "alma-fragnesia-kernel-patched", "AlmaLinux kernel is at or above the built-in Fragnesia patched version.", `${kernelRelease} >= ${patched}`, "Keep following vendor advisories for later kernel updates.");
  }
}

function checkKernelModules(findings, targetRoot) {
  const modulesText = readText(mapLinuxPath(targetRoot, "/proc/modules"));
  const modprobeDir = mapLinuxPath(targetRoot, "/etc/modprobe.d");
  if (!modulesText && !exists(modprobeDir)) {
    return;
  }

  const loaded = new Set(
    modulesText
      .split(/\r?\n/)
      .map((line) => line.split(/\s+/)[0])
      .filter(Boolean)
  );
  const risky = ["esp4", "esp6", "rxrpc"].filter((name) => loaded.has(name));
  if (risky.length > 0) {
    addFinding(findings, "warning", "fragnesia-risk-modules-loaded", "Fragnesia-related kernel modules are currently loaded.", risky.join(", "), "If these modules are not required for IPsec ESP or AFS/rxrpc workloads, apply vendor-approved mitigations and patch/reboot.");
  }

  const modprobeText = readDirectoryText(modprobeDir);
  const missing = ["esp4", "esp6", "rxrpc"].filter((name) => {
    const pattern = new RegExp(`install\\s+${escapeRegExp(name)}\\s+/bin/false`);
    return !pattern.test(modprobeText);
  });
  if (missing.length > 0) {
    addFinding(findings, "review", "fragnesia-module-blacklist-not-confirmed", "Temporary Fragnesia module blacklist was not fully confirmed.", `missing install /bin/false entries: ${missing.join(", ")}`, "This is only a mitigation check. Prefer patched kernels and reboot when available.");
  }
}

function checkPersistence(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const candidates = [
    "/etc/systemd/system/pgsql-monitor.service",
    "/usr/bin/pgmonitor.py",
    "/tmp/transformers.pyz",
    homeRelative ? `${homeRelative}/.config/systemd/user/gh-token-monitor.service` : "",
    homeRelative ? `${homeRelative}/.local/bin/gh-token-monitor.sh` : "",
    homeRelative ? `${homeRelative}/.config/gh-token-monitor` : "",
    homeRelative ? `${homeRelative}/.config/systemd/user/pgsql-monitor.service` : "",
    homeRelative ? `${homeRelative}/.local/bin/pgmonitor.py` : "",
  ].filter(Boolean);

  for (const candidate of candidates) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      addFinding(findings, "critical", "known-supply-chain-persistence-path", "Known supply-chain persistence or payload path exists.", candidate, "Contain the host and preserve evidence. Remove persistence from a trusted recovery posture before rotating tokens.");
    }
  }
}

function checkDprkNpmRat(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    for (const packageName of KNOWN_DPRK_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "dprk-npm-rat-package-reference", "Known DPRK npm RAT package name appears in dependency metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. Inspect from a clean posture and rotate credentials if execution is suspected.");
      }
    }
    for (const indicator of DPRK_NPM_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "dprk-npm-rat-text-indicator", "DPRK npm RAT behavior indicator appears in dependency metadata.", `${relative}: ${indicator}`, "Review the referenced package scripts and lockfile entries before running package manager commands.");
      }
    }
  }
}

function checkCompromisedNpmPackages(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    for (const packageName of KNOWN_COMPROMISED_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "compromised-npm-package-reference", "Known compromised npm package appears in dependency metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. Isolate affected systems if execution is suspected and rotate secrets from a clean posture.");
      }
    }
  }
}

function checkAtomicArchAurCompromise(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/tmp",
    "/var/tmp",
    "/var/cache",
    "/var/lib/pacman/local",
    "/opt",
    "/srv",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text || !text.includes(ATOMIC_ARCH_AUR_PACKAGE)) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const base = path.basename(filePath);
    const isAurBuildFile = base === "PKGBUILD" || base === ".SRCINFO" || base.endsWith(".install");

    if (isAurBuildFile) {
      addFinding(findings, "critical", "atomicarch-aur-atomic-lockfile-reference", "AUR build metadata references the malicious atomic-lockfile npm package.", `${relative}: ${ATOMIC_ARCH_AUR_PACKAGE}`, "Do not build or install this AUR package. Preserve the PKGBUILD/install hook, remove the package from any build queue, and rotate developer credentials if it may have executed.");
    }

    if (isAurBuildFile && /\b(?:npm\s+(?:install|i|exec|x)|npx)\b/i.test(text)) {
      addFinding(findings, "critical", "atomicarch-aur-npm-loader", "AUR build/install script invokes npm while referencing atomic-lockfile.", relative, "Treat as AtomicArch/IronWorm-style AUR supply-chain compromise. If installed, isolate the host and rotate GitHub, npm, SSH, Vault, Docker/Podman, browser, and chat credentials from a clean machine.");
    }

    if (/eBPF|rootkit|\bdeps\b|browser cookies?|Vault|Docker|Podman|Slack|Discord|Teams/i.test(text)) {
      addFinding(findings, "warning", "atomicarch-payload-text-indicator", "AtomicArch/IronWorm payload behavior terms appear near atomic-lockfile.", relative, "Correlate with AUR install history, npm cache, package build artifacts, process/module state, and credential exposure.");
    }
  }
}

function checkOtterCookieNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of OTTERCOOKIE_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "ottercookie-npm-package-reference", "Panther OtterCookie npm campaign package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. If install occurred, inspect for Vercel C2 traffic, SSH authorized_keys modification, and rotate developer secrets from a clean posture."); // push-guard: ignore
      }
    }

    for (const indicator of OTTERCOOKIE_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "ottercookie-text-indicator", "OtterCookie npm behavior or C2 indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with npm install history, outbound traffic, shell history, ~/.ssh/authorized_keys, and firewall changes before cleanup."); // push-guard: ignore
      }
    }
  }
}

function checkSolanaFakeFix(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/usr/local/lib/python3",
    "/usr/lib/python3",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of SOLANA_FAKEFIX_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "solana-fakefix-npm-package-reference", "JFrog Solana FakeFix / CMS loader npm package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. If install/import occurred, rotate Solana wallets, SSH keys, cloud credentials, source-control tokens, npm tokens, and CI secrets from a clean posture.");
      }
    }

    for (const packageName of SOLANA_FAKEFIX_PYPI_PACKAGES) {
      if (pythonPackageNameInText(text, packageName)) {
        addFinding(findings, "critical", "solana-fakefix-pypi-package-reference", "JFrog Solana FakeFix PyPI package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not import this package or run Python package-manager commands in this environment. If import occurred, rotate Solana wallets, SSH keys, cloud credentials, source-control tokens, PyPI tokens, and CI secrets from a clean posture.");
      }
    }

    for (const indicator of SOLANA_FAKEFIX_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "solana-fakefix-text-indicator", "Solana FakeFix / CMS loader behavior indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with package metadata, npm/PyPI install history, shell profiles, cron, LaunchAgents, Registry/Run-key equivalents, and network telemetry before cleanup.");
      }
    }
  }
}

function checkHadesPyPi(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const runtimePaths = [
    joinParts("/tmp/.bun", "_ran"),
    "/tmp/b.zip",
    "/tmp/b/bun",
    joinParts("/tmp/.sshu", "-setup.js"),
    joinParts("/var/tmp/.bun", "_ran"),
    "/var/tmp/b.zip",
    "/var/tmp/b/bun",
  ];
  for (const runtimePath of runtimePaths) {
    if (exists(mapLinuxPath(targetRoot, runtimePath))) {
      addFinding(findings, "warning", "hades-runtime-artifact-path", "Hades Bun/SSH runtime artifact path exists.", runtimePath, "Preserve evidence before cleanup. If package execution is suspected, isolate the host and rotate developer/package/cloud credentials from a clean posture.");
    }
  }

  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib",
    "/usr/lib/python3",
    "/usr/lib64/python3",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findHadesFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const base = path.basename(filePath);
    if (/-setup\.pth$/i.test(base)) {
      addFinding(findings, "warning", "hades-pth-startup-hook-file", "Hades-style Python startup hook filename appears in scanned host tree.", relative, "Review the .pth file before starting Python in this environment. Executable .pth lines can run on Python startup.");
    }
    if (base === "_index.js" && /site-packages|\.venv|\/venv\/|\.dist-info|\.whl|py3-none-any/i.test(relative)) {
      addFinding(findings, "warning", "hades-python-payload-filename", "Hades-style _index.js payload filename appears in a Python package context.", relative, "Treat this environment as suspicious until the package provenance and payload content are reviewed.");
    }
    if (HADES_NATIVE_EXTENSION_FILES.has(base)) {
      addFinding(findings, "critical", "hades-known-native-extension", "Native extension filename reported in Hades PyPI artifacts exists.", relative, "Contain the environment and preserve the wheel/site-packages directory for incident response.");
    } else if (base.endsWith(".abi3.so") && exists(path.join(path.dirname(filePath), "_index.js"))) {
      addFinding(findings, "warning", "hades-native-extension-payload-pair", "Python native extension is paired with _index.js.", relative, "Review for Hades-style import-time JavaScript launcher behavior before importing the package.");
    }

    const text = readText(filePath);
    if (!text) continue;
    for (const [packageName, versions] of Object.entries(HADES_PYPI_PACKAGES)) {
      for (const version of versions) {
        if (pythonPackageVersionInText(text, packageName, version)) {
          addFinding(findings, "critical", "hades-pypi-package-version", "Known Hades PyPI package version appears in scanned metadata.", `${relative}: ${packageName}==${version}`, "Do not run Python/package-manager commands in this environment. Pin away from the affected version and rotate credentials if execution may have occurred.");
        }
      }
    }
    if (isHadesPthBunLoader(text)) {
      addFinding(findings, "critical", "hades-pth-bun-loader", "Executable Python startup hook appears to bootstrap Bun and launch _index.js.", relative, "Treat Python startup in this environment as possible payload execution. Preserve artifacts and rotate exposed credentials from a clean machine.");
    }
    if (/sys\.path/i.test(text) && /_index\.js/i.test(text) && /bun|subprocess/i.test(text)) {
      addFinding(findings, "critical", "hades-syspath-payload-loader", "Python code searches sys.path for _index.js and attempts Bun/subprocess execution.", relative, "Review for the Hades loader/payload split before running Python or package tools.");
    }
    if (
      base === "_index.js" &&
      /(?:unrestricted\s+mode|safety\s+guidelines|guardrails)/i.test(text) &&
      /(?:biological|nuclear)\s+weapons?/i.test(text)
    ) {
      addFinding(findings, "warning", "hades-llm-anti-analysis-bait", "Hades-style LLM refusal-bait appears in a Python package JavaScript payload.", relative, "Do not feed the raw payload to an LLM triage flow. Use static extraction, YARA, deobfuscation, and behavioral review from a clean posture.");
    }
    for (const indicator of HADES_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "hades-text-indicator", "Hades PyPI campaign indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with installed package versions, Python startup hooks, CI artifacts, and credential exposure.");
      }
    }
  }
}

function checkDynatraceTeamPcpWatch(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/etc",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const tokenMatches = Array.from(new Set(text.match(DYNATRACE_TOKEN_PATTERN) || []));
    for (const token of tokenMatches) {
      addFinding(findings, "critical", "dynatrace-token-exposure", "Dynatrace token-shaped credential appears in scanned metadata.", `${relative}: ${redactDynatraceToken(token)}`, "Treat as a credential exposure. Rotate the token from a clean posture, review scopes, and audit Dynatrace/API usage around the exposure window.");
    }

    for (const term of DYNATRACE_TEAMPCP_REPO_TERMS) {
      if (text.includes(term)) {
        addFinding(findings, "warning", "dynatrace-teampcp-repo-term", "TeamPCP/Dynatrace screenshot repo term appears in scanned metadata.", `${relative}: ${term}`, "Weak signal only: preserve the file, identify whether the term belongs to an expected Dynatrace-controlled source, and correlate with package, CI, and repository access logs.");
      }
    }

    for (const term of DYNATRACE_TEAMPCP_SERVICE_TERMS) {
      if (text.includes(term)) {
        addFinding(findings, "warning", "dynatrace-teampcp-service-term", "TeamPCP/Dynatrace screenshot service term appears in scanned metadata.", `${relative}: ${term}`, "Weak signal only: correlate with repository visibility, CI logs, package metadata, and token rotation status. This finding does not prove compromise by itself.");
      }
    }
  }
}

function checkPcpJackRelayArtifacts(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const candidatePaths = [
    "/var/tmp/.xs",
    "/tmp/.ch",
    "/tmp/.ch2",
    "/tmp/.ch3",
    "/tmp/.ch4",
    "/tmp/.ch5",
    "/etc/systemd/system/xsync.service",
    "/root/.sliver-client/configs/root_localhost.cfg",
    "/root/excalibur/smtp_proxies.csv",
    homeRelative ? `${homeRelative}/.config/systemd/user/xsync.service` : "",
  ].filter(Boolean);

  for (const candidate of candidatePaths) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      addFinding(findings, "warning", "pcpjack-relay-artifact-path", "PCPJack/Chisel SMTP relay artifact path exists.", candidate, "Review for Sliver/Chisel relay persistence. Preserve evidence and inspect cron/systemd before cleanup.");
    }
  }

  const cronText = [
    readText(mapLinuxPath(targetRoot, "/etc/crontab")),
    readDirectoryText(mapLinuxPath(targetRoot, "/etc/cron.d")),
    homeRelative ? readDirectoryText(mapLinuxPath(targetRoot, `${homeRelative}/.config/systemd/user`)) : "",
    homeRelative ? readDirectoryText(mapLinuxPath(targetRoot, `${homeRelative}/.local/share/systemd/user`)) : "",
  ].join("\n");
  if (/#\s*xsync\b|\bxsync\b.*\/var\/tmp\/\.xs|\/var\/tmp\/\.xs.*\bxsync\b/i.test(cronText)) {
    addFinding(findings, "warning", "pcpjack-xsync-persistence-marker", "xsync persistence marker references the PCPJack /var/tmp/.xs Chisel relay path.", "xsync + /var/tmp/.xs", "Review cron and systemd user services for Chisel relay watchdog persistence.");
  }

  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    if (PCPJACK_FILE_NAMES.has(path.basename(filePath))) {
      addFinding(findings, "warning", "pcpjack-relay-file-name", "PCPJack/Chisel relay file name appears in scanned host tree.", relative, "Review this file for SMTP relay, Sliver, Chisel, or proxy fleet state.");
    }
    const text = readText(filePath);
    if (!text) continue;
    for (const indicator of PCPJACK_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "pcpjack-relay-text-indicator", "PCPJack/Chisel SMTP relay indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with process, cron, systemd, Sliver, and outbound SMTP relay logs.");
      }
    }
  }
}

function checkGentlemenRansomware(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/mnt",
    "/media",
    "/ProgramData",
    "/Users",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const baseLower = base.toLowerCase();
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const size = fileSizeBytes(filePath);

    if (baseLower === "gentlemen.bmp" || base === "README-GENTLEMEN.txt") {
      addFinding(findings, "critical", "gentlemen-ransomware-note-wallpaper", "Gentlemen ransomware ransom-note or wallpaper filename exists.", relative, "Treat this as a high-confidence ransomware artifact. Isolate the host, preserve timestamps and file metadata, and review clean backups before any cleanup.");
    }

    if (GENTLEMEN_TOOLKIT_FILES.has(base)) {
      addFinding(findings, "warning", "gentlemen-toolkit-file-name", "Gentlemen exposed operator-toolkit filename exists.", relative, "Review for staged defense-evasion, remote-access, network-scan, or credential-dump tooling. Preserve evidence before deleting files.");
    }

    if (baseLower === "psexec.exe") {
      addFinding(findings, "review", "gentlemen-psexec-dropper-name", "PsExec filename appears in a scanned host or mounted-root tree.", relative, "PsExec can be legitimate. Correlate with Gentlemen spread flags, remote execution logs, and surrounding toolkit files before treating it as malicious.");
    }

    if (shouldHashGentlemenArtifact(base) && size > 0 && size <= 100 * 1024 * 1024) {
      const digest = sha256File(filePath);
      const label = GENTLEMEN_KNOWN_HASHES.get(digest);
      if (label) {
        addFinding(findings, "critical", "gentlemen-known-hash", "Known Gentlemen ransomware-related SHA-256 observed.", `${relative}: ${label}; sha256=${digest}`, "Contain the host and preserve the file for incident response. Do not execute the file.");
      }
    }

    const text = size <= 1024 * 1024 ? readText(filePath) : "";
    if (!text) continue;

    if (/\bgentlemen_system\b|LOCKER_BACKGROUND=1|README-GENTLEMEN\.txt|gentlemen\.bmp|\b(?:UpdateSystem|UpdateUser|GupdateS|GupdateU)\b/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-encryptor-runtime-marker", "Gentlemen ransomware runtime marker appears in scanned host metadata.", relative, "Review process, service, scheduled-task, wallpaper, ransom-note, and filesystem activity around this path.");
    }

    if (/\bpsexec(?:\.exe)?\b[\s\S]{0,240}(?:--spread|--ip|--login|--password)|(?:--spread|--ip|--login|--password)[\s\S]{0,240}\bpsexec(?:\.exe)?\b/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-self-propagation-marker", "Gentlemen-style PsExec self-propagation marker appears in scanned text.", relative, "Correlate with Windows event logs, SMB/admin-share access, command history, and lateral-movement evidence.");
    }

    if (/(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+\/set|wevtutil\s+cl|cipher\s+\/w|taskkill\b|sc\s+stop\b|net\s+stop\b|dControl\.exe|ConfigureDefender\.exe|PCHunter64_new\.exe|PowerTool64_new\.exe|WinDefGpo_Reg\.ps1|enable_dump_pass\.reg)/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-defense-evasion-command-marker", "Gentlemen toolkit or ransomware defense-evasion command marker appears in scanned text.", relative, "Review whether this is approved administration, attacker staging, or ransomware pre-encryption activity.");
    }

    for (const indicator of GENTLEMEN_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "gentlemen-network-indicator", "Gentlemen ransomware campaign network or session indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with firewall, proxy, EDR, and remote-access logs. Preserve evidence and rotate credentials from a clean posture if compromise is confirmed.");
      }
    }
  }
}

function checkPeopleSoftCve202635273(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/u01",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();

    if (base === PEOPLESOFT_EXTORTION_MARKER) {
      addFinding(findings, "critical", "peoplesoft-shinyhunters-extortion-marker", "PeopleSoft/ShinyHunters extortion marker filename exists.", relative, "Contain the affected PeopleSoft/WebLogic host, preserve evidence, and review Oracle/Mandiant remediation guidance before cleanup.");
    }

    if (PEOPLESOFT_MESH_AGENT_FILES.has(base)) {
      addFinding(findings, "critical", "peoplesoft-meshcentral-masquerade-agent", "MeshCentral agent filename used in the PeopleSoft/ShinyHunters campaign exists.", relative, "Treat as possible remote-management persistence. Isolate the host and preserve the binary for incident response.");
    }

    if (loweredRelative.includes("/psemhub.war/") && loweredRelative.endsWith(".jsp")) {
      addFinding(findings, "critical", "peoplesoft-psemhub-unexpected-jsp", "JSP file exists under PSEMHUB.war.", relative, "Mandiant recommends reviewing PSEMHUB.war for JSP files not shipped with the product. Treat unexpected JSP files as potential web shells.");
    }

    if (loweredRelative.includes("/psemhub.war/envmetadata/transactions/")) {
      addFinding(findings, "warning", "peoplesoft-psemhub-transaction-artifact", "File exists under PSEMHUB.war envmetadata transaction paths.", relative, "Review for CVE-2026-35273 exploitation artifacts and preserve timestamps before cleanup.");
    }

    if (/\/psemhub\.war\/(?:logs|persistantstorage|scratchpad)(?:\/|$)/i.test(relative)) {
      addFinding(findings, "warning", "peoplesoft-psemhub-unexpected-directory", "Unexpected PSEMHUB.war directory path reported in exploitation triage exists.", relative, "Review the directory contents and correlate with PeopleSoft/WebLogic access logs.");
    }

    const text = readText(filePath);
    if (!text) continue;

    if (/PeopleTools[^0-9]{0,40}8\.6[12]\b|PeopleSoft Enterprise PeopleTools[^0-9]{0,80}8\.6[12]\b/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-cve-2026-35273-affected-version", "Text references PeopleSoft PeopleTools 8.61 or 8.62, affected by CVE-2026-35273.", relative, "Apply Oracle's June 10, 2026 Security Alert mitigation or patch guidance and restrict PSEMHUB access.");
    }

    if (/\/PSEMHUB\/hub|\/PSIGW\/HttpListeningConnector/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-psemhub-route-review", "File references PeopleSoft PSEMHUB or PSIGW routes used in CVE-2026-35273 triage.", relative, "Review whether these routes are externally reachable or appear in PIA WebLogic access logs from untrusted IPs.");
    }

    for (const indicator of PEOPLESOFT_CAMPAIGN_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "peoplesoft-shinyhunters-network-indicator", "PeopleSoft/ShinyHunters campaign network indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with outbound firewall, NetFlow, WebLogic, and MeshCentral activity. Preserve evidence before rotating credentials from a clean posture.");
      }
    }

    if (/meshctrl\.js\s+RunCommand|README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED\.TXT|_fanout\.sh|psappsrv\.cfg|\/etc\/hosts.*csprd/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-shinyhunters-operator-artifact", "Text contains PeopleSoft/ShinyHunters operator or reconnaissance artifacts.", relative, "Review shell history, WebLogic logs, process scheduler paths, and lateral movement evidence.");
    }
  }
}

function checkLiteLlmGatewayExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasLiteLlm = hasAnyTerm(text, LITELLM_CONFIG_TERMS);
    const liteLlmVersions = packageVersionsInText(text, "litellm");
    const starletteVersions = packageVersionsInText(text, "starlette");

    for (const version of liteLlmVersions) {
      if (isVersionInRange(version, LITELLM_AFFECTED_MIN, LITELLM_FIXED)) {
        addFinding(findings, "critical", "litellm-cve-2026-42271-vulnerable-version", "LiteLLM dependency is in the CVE-2026-42271 affected range.", `${relative}: litellm ${version}`, `Upgrade LiteLLM to ${LITELLM_FIXED} or newer, restrict admin/MCP routes, and rotate proxy/provider credentials if exposure is suspected.`);
      }
    }

    if (hasLiteLlm) {
      for (const version of starletteVersions) {
        if (compareDottedVersion(version, STARLETTE_FIXED) < 0) {
          addFinding(findings, "warning", "litellm-starlette-host-header-chain", "LiteLLM appears with a Starlette version vulnerable to the Host-header authentication-bypass chain.", `${relative}: starlette ${version}`, `Upgrade Starlette to ${STARLETTE_FIXED} or newer, then review LiteLLM authentication and reverse-proxy Host-header handling.`);
        }
      }
    }

    if (hasLiteLlm && exposesAllInterfaces(text)) {
      addFinding(findings, "warning", "litellm-public-bind", "LiteLLM-related config appears to bind a service to all interfaces.", relative, "Bind the LiteLLM proxy to localhost/private interfaces unless deliberate, and place admin/MCP routes behind trusted network controls.");
    }

    for (const route of LITELLM_MCP_TEST_ROUTES) {
      if (text.includes(route)) {
        addFinding(findings, "warning", "litellm-mcp-test-route-reference", "LiteLLM MCP test endpoint route appears in scanned config or source.", `${relative}: ${route}`, "If this route is reachable, block it at the reverse proxy/API gateway or require admin-only access.");
      }
    }

    if (hasLiteLlm && /Host\s*[:=]|host_header|trusted_hosts|allowed_hosts/i.test(text)) {
      addFinding(findings, "review", "litellm-host-header-review", "LiteLLM-related config mentions Host-header or trusted-host handling.", relative, "Review for Starlette Host-header bypass exposure and require strict trusted-host validation.");
    }

    if (hasLiteLlm) {
      const keyTerms = PROVIDER_KEY_ENV_TERMS.filter((term) => text.includes(term));
      if (keyTerms.length > 0) {
        addFinding(findings, "review", "litellm-provider-key-blast-radius", "LiteLLM-related config references provider credential environment names.", `${relative}: ${keyTerms.join(", ")}`, "Do not print secret values. If the proxy was exposed, rotate provider/proxy keys from a clean posture.");
      }
    }
  }
}

function checkOpenClawAgentExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const maybeOpenClaw =
      /\bopenclaw\b/i.test(text) ||
      isOpenClawConfigFileName(path.basename(filePath)) ||
      relative.toLowerCase().includes("/openclaw/") ||
      /\bdmPolicy\b|\ballowFrom\b|agents\.defaults\.sandbox/i.test(text);
    if (!maybeOpenClaw) continue;

    const openClawVersions = packageVersionsInText(text, "openclaw");
    for (const version of openClawVersions) {
      if (compareDottedVersion(version, OPENCLAW_FIXED) < 0) {
        addFinding(findings, "warning", "openclaw-vulnerable-version", "OpenClaw version predates the message-object prompt-boundary fix.", `${relative}: openclaw ${version}`, `Upgrade OpenClaw to ${OPENCLAW_FIXED} or newer before exposing message channels.`);
      }
    }

    const hasOpenDmPolicy = /\bdmPolicy["']?\s*[:=]\s*["']open["']/i.test(text);
    const hasWildcardAllowFrom = /\ballowFrom["']?\s*[:=][\s\S]{0,160}["']\*["']/i.test(text);
    const hasDisabledSandbox = /(?:agents\.defaults\.sandbox\.mode|sandbox[\s\S]{0,80}\bmode)["']?\s*[:=]\s*["'](?:none|off|host|main|disabled)["']/i.test(text);

    if (hasOpenDmPolicy && hasWildcardAllowFrom) {
      addFinding(findings, "warning", "openclaw-open-dm-wildcard", "OpenClaw config appears to allow public inbound DMs with a wildcard allowlist.", relative, "Require pairing or stable sender allowlists before enabling agent actions from messaging channels.");
    }

    if (hasOpenDmPolicy && hasDisabledSandbox) {
      addFinding(findings, "warning", "openclaw-open-dm-unsandboxed", "OpenClaw config appears to combine open inbound DMs with host/main/disabled sandbox mode.", relative, "Route untrusted channels to sandboxed non-main agents and gate outbound mail, credential forwarding, shell, and file actions.");
    }
  }
}

function checkAgentjackingSentryMcpExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasSentry = hasAnyTerm(text, AGENTJACKING_SENTRY_TERMS);
    const hasMcp = hasAnyTerm(text, AGENTJACKING_MCP_TERMS);

    if (hasSentry && hasMcp) {
      addFinding(findings, "review", "agentjacking-sentry-mcp-review", "Sentry appears wired into an MCP/agent context.", relative, "Treat Sentry event content as untrusted tool output. Require human approval before agents execute commands suggested by Sentry issues.");
    }

    if (
      /(?:##\s*Resolution|resolution\s*:)/i.test(text) &&
      /\bnpx\b/i.test(text) &&
      /sentry|Sentry|event|issue|error/i.test(text)
    ) {
      addFinding(findings, "warning", "agentjacking-sentry-resolution-npx", "Sentry-style resolution content attempts npm execution.", relative, "Review for Agentjacking-style indirect prompt injection before giving this content to a coding agent.");
    }

    if (/advisory-tracker\.com|X-Tenet-Security|ResponsibleDisclosure\s*\[SECURITY SCAN\]/i.test(text)) {
      addFinding(findings, "review", "agentjacking-tenet-validation-marker", "Tenet Agentjacking validation marker appears in scanned host metadata.", relative, "Correlate with Sentry events, agent command history, package-manager logs, and developer credential exposure.");
    }
  }
}

function checkNpmV12Readiness(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (base === "package.json") {
      const npmVersions = npmVersionsInText(text);
      for (const version of npmVersions) {
        if (compareDottedVersion(version, NPM_V12_PREPARE_MIN) < 0) {
          addFinding(findings, "review", "npm-v12-prep-old-npm-pin", "Project pins npm older than the npm v12 migration-warning release.", `${relative}: npm ${version}`, `Use npm ${NPM_V12_PREPARE_MIN} or newer to review install-script and non-registry-source warnings before npm v12.`);
        }
      }
    }

    if (DEPENDENCY_FILE_NAMES.has(base)) {
      if (/"hasInstallScript"\s*:\s*true/i.test(text) && !/"allowScripts"\s*:/i.test(text)) {
        addFinding(findings, "review", "npm-v12-install-script-approval-review", "Dependency metadata records install scripts without visible npm approval metadata.", relative, "Run npm 11.16+ and review npm approve-scripts output before npm v12.");
      }
      if (/"https?:\/\/[^"]+\.(?:tgz|tar\.gz)(?:[?#][^"]*)?"/i.test(text)) {
        addFinding(findings, "review", "npm-v12-remote-tarball-review", "Dependency metadata references a remote tarball URL.", relative, "npm v12 requires explicit --allow-remote approval for remote URL dependencies.");
      }
      if (/github\.com[:/][^\s"']+|(?:git\+https?|git):\/\/[^\s"']+|github:/i.test(text)) {
        addFinding(findings, "review", "npm-v12-git-dependency-review", "Dependency metadata references a Git dependency source.", relative, "npm v12 requires explicit --allow-git approval for Git dependencies.");
      }
    }

    if (base === ".npmrc") {
      if (/^\s*ignore-scripts\s*=\s*true\s*$/im.test(text)) {
        addFinding(findings, "info", "npm-v12-ignore-scripts-migration-note", ".npmrc uses ignore-scripts=true.", relative, "npm approve-scripts can still list pending approvals, but ignore-scripts takes precedence until removed.");
      }
      if (/^\s*allow-git\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-git", ".npmrc broadly allows Git dependency resolution.", relative, "npm v12 defaults --allow-git to none; keep approvals narrow and intentional.");
      }
      if (/^\s*allow-remote\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-remote", ".npmrc broadly allows remote URL dependency resolution.", relative, "npm v12 defaults --allow-remote to none; keep approvals narrow and intentional.");
      }
      if (/^\s*allow-scripts\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-scripts", ".npmrc broadly allows install scripts.", relative, "npm v12 moves install-script execution to explicit package approvals.");
      }
    }
  }
}

function checkOperationHighlandAuthStack(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";

  for (const candidate of OPERATION_HIGHLAND_IOC_PATHS) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      const severity = OPERATION_HIGHLAND_LOWER_CONFIDENCE_PATHS.has(candidate) ? "warning" : "critical";
      addFinding(findings, severity, "operation-highland-ioc-path", "Sygnia Operation Highland / Velvet Ant IOC path exists.", candidate, "Treat as possible Linux authentication-stack compromise. Isolate or snapshot the host, preserve evidence, and validate PAM/OpenSSH from trusted media before rotating credentials.");
    }
  }

  const hashCandidates = new Set([...OPERATION_HIGHLAND_AUTH_FILES, ...OPERATION_HIGHLAND_IOC_PATHS]);
  if (OPERATION_HIGHLAND_SHA1_HASHES.size > 0) {
    for (const candidate of hashCandidates) {
      const resolved = mapLinuxPath(targetRoot, candidate);
      const size = fileSizeBytes(resolved);
      if (!isFile(resolved) || size <= 0 || size > 250 * 1024 * 1024) continue;
      const digest = sha1File(resolved);
      if (OPERATION_HIGHLAND_SHA1_HASHES.has(digest)) {
        addFinding(findings, "critical", "operation-highland-known-sha1", "Known Sygnia Operation Highland / Velvet Ant SHA-1 observed.", `${candidate}: sha1=${digest}`, "Preserve the file and compare package ownership/integrity from a clean environment. Do not trust local credentials until persistence is removed.");
      }
    }
  }

  const roots = [
    homeRelative,
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/share/nginx",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const text = readText(filePath);

    if (OPERATION_HIGHLAND_FILE_NAMES.has(base)) {
      addFinding(findings, "warning", "operation-highland-tool-filename", "Operation Highland / Velvet Ant filename appears in scanned host tree.", relative, "Review the file provenance, ownership, package integrity, timestamps, and surrounding persistence before cleanup.");
    }

    if (!text) continue;

    for (const indicator of OPERATION_HIGHLAND_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "operation-highland-network-indicator", "Operation Highland / Velvet Ant C2 or infrastructure indicator appears in scanned metadata.", `${relative}: ${indicator}`, "Correlate with DNS, proxy, firewall, SSH, and process telemetry. Preserve evidence and avoid credential rotation until persistence has been removed.");
      }
    }

    for (const indicator of OPERATION_HIGHLAND_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "operation-highland-text-indicator", "Operation Highland / Velvet Ant behavior indicator appears in scanned metadata.", `${relative}: ${indicator}`, "Review for backdoored PAM/OpenSSH logging, FastCGI bridge execution, and hidden credential-log paths.");
      }
    }

    for (const indicator of OPERATION_HIGHLAND_PROCESS_MASQUERADE) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "operation-highland-process-masquerade-indicator", "Operation Highland / Velvet Ant process-masquerade marker appears in scanned metadata.", `${relative}: ${indicator}`, "Correlate with process listings, systemd/init entries, shell history, and recovered binaries.");
      }
    }
  }
}

function checkTransformersPayload(findings, targetRoot) {
  const payloadPath = mapLinuxPath(targetRoot, "/tmp/transformers.pyz");
  if (!exists(payloadPath) || !isFile(payloadPath)) {
    return;
  }

  const digest = sha256File(payloadPath);
  const severity = KNOWN_HASHES.has(digest) ? "critical" : "warning";
  addFinding(findings, severity, "transformers-pyz-present", "A transformers.pyz payload file exists under /tmp.", `sha256=${digest}`, "Preserve the file and metadata for incident response. Do not execute it.");
}

function checkSecretSurfaces(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  if (!homeRelative) {
    return;
  }

  const surfaces = [
    `${homeRelative}/.aws/credentials`,
    `${homeRelative}/.config/gh/hosts.yml`,
    `${homeRelative}/.npmrc`,
    `${homeRelative}/.pypirc`,
    `${homeRelative}/.docker/config.json`,
    `${homeRelative}/.kube/config`,
    `${homeRelative}/.ssh`,
  ];

  const present = surfaces.filter((surface) => exists(mapLinuxPath(targetRoot, surface)));
  if (present.length > 0) {
    addFinding(findings, "review", "developer-secret-surfaces-present", "Developer credential surfaces are present.", present.join(", "), "This tool does not read or print secrets. If payload execution is confirmed, rotate credentials from a clean machine.");
  }
}

function addFinding(findings, severity, id, title, evidence, guidance) {
  findings.push({ severity, id, title, evidence, guidance });
}

function summarize(findings) {
  const summary = { critical: 0, warning: 0, review: 0, info: 0, overall: "info" };
  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] || 0) + 1;
  }
  if (summary.critical > 0) summary.overall = "critical";
  else if (summary.warning > 0) summary.overall = "warning";
  else if (summary.review > 0) summary.overall = "review";
  return summary;
}

function mapLinuxPath(root, linuxPath) {
  const clean = linuxPath.replace(/^\/+/, "").replace(/\//g, path.sep);
  return path.join(root, clean);
}

function stripRoot(inputPath, root) {
  const resolvedInput = path.resolve(inputPath);
  const resolvedRoot = path.resolve(root);
  if (resolvedInput.toLowerCase().startsWith(resolvedRoot.toLowerCase())) {
    const relative = path.relative(resolvedRoot, resolvedInput).replace(/\\/g, "/");
    return `/${relative}`;
  }
  return inputPath.startsWith("/") ? inputPath : `/${inputPath.replace(/\\/g, "/")}`;
}

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (_error) {
    return "";
  }
}

function readDirectoryText(dirPath) {
  let output = "";
  for (const filePath of walkFiles(dirPath)) {
    output += `\n${readText(filePath)}`;
  }
  return output;
}

function walkFiles(dirPath) {
  const files = [];
  if (!exists(dirPath)) return files;
  const stack = [dirPath];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(fullPath);
      else if (entry.isFile()) files.push(fullPath);
    }
  }
  return files;
}

function findDependencyFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && DEPENDENCY_FILE_NAMES.has(entry.name)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findWatchFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", ".venv", "venv"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isWatchFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findHadesFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isHadesWatchFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function isWatchFile(fileName, filePath) {
  if (WATCH_FILE_NAMES.has(fileName)) return true;
  const extension = path.extname(fileName);
  if (!WATCH_FILE_EXTENSIONS.has(extension)) return false;
  try {
    return fs.statSync(filePath).size <= 1024 * 1024;
  } catch (_error) {
    return false;
  }
}

function isHadesWatchFile(fileName, filePath) {
  if (isWatchFile(fileName, filePath)) return true;
  if (fileName === "_index.js" || /-setup\.pth$/i.test(fileName) || HADES_NATIVE_EXTENSION_FILES.has(fileName)) return true;
  if (fileName.endsWith(".abi3.so")) return true;
  return false;
}

function isAstroConfigFileName(fileName) {
  return /^astro\.config\.(js|cjs|mjs|ts|mts|cts)$/i.test(fileName);
}

function isOpenClawConfigFileName(fileName) {
  return OPENCLAW_CONFIG_FILES.has(fileName.toLowerCase()) || /^openclaw\.(json|jsonc|yaml|yml|toml)$/i.test(fileName);
}

function shouldHashGentlemenArtifact(fileName) {
  const lower = fileName.toLowerCase();
  return GENTLEMEN_TOOLKIT_FILES.has(fileName) || lower === "psexec.exe" || lower === "gentlemen.bmp" || lower.endsWith(".exe") || lower.endsWith(".bmp");
}

function astroConfigLineHasLoaderSignal(line) {
  return /createRequire|eval\s*\(|Function\s*\(|global\s*(?:\.|\[)|Buffer\.from|https?\.|\.request\s*\(|\.get\s*\(|fetch\s*\(|trongrid|aptoslabs|bsc-dataseed|publicnode/i.test(line);
}

function redactDynatraceToken(token) {
  const parts = token.split(".");
  if (parts.length < 3) return "dt0***";
  return `${parts[0]}.${parts[1]}.<redacted>`;
}

function readOsRelease(text) {
  const result = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!match) continue;
    result[match[1]] = match[2].replace(/^"/, "").replace(/"$/, "");
  }
  return result;
}

function compareKernelRelease(a, b) {
  const left = tokenizeKernel(a);
  const right = tokenizeKernel(b);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] ?? 0;
    const r = right[i] ?? 0;
    if (typeof l === "number" && typeof r === "number" && l !== r) return l > r ? 1 : -1;
    const ls = String(l);
    const rs = String(r);
    if (ls !== rs) return ls > rs ? 1 : -1;
  }
  return 0;
}

function tokenizeKernel(value) {
  return String(value)
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part));
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function sha1File(filePath) {
  const hash = crypto.createHash("sha1");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function loadHashSet(fileName) {
  try {
    const raw = fs.readFileSync(path.join(__dirname, "..", "data", fileName), "utf8");
    return new Set(JSON.parse(raw));
  } catch (_error) {
    return new Set();
  }
}

function exists(filePath) {
  try {
    fs.accessSync(filePath);
    return true;
  } catch (_error) {
    return false;
  }
}

function isFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (_error) {
    return false;
  }
}

function fileSizeBytes(filePath) {
  try {
    return fs.statSync(filePath).size;
  } catch (_error) {
    return 0;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasAnyTerm(text, terms) {
  return terms.some((term) => text.includes(term));
}

function exposesAllInterfaces(text) {
  return /\b(0\.0\.0\.0|\[::\]|::)\b/.test(text) || /--host\s+0\.0\.0\.0\b/i.test(text);
}

function packageVersionsInText(text, packageName) {
  const escaped = escapeRegExp(packageName);
  const versions = new Set();
  const patterns = [
    new RegExp(`\\b${escaped}\\b\\s*(?:==|===|=|~=|>=|<=|>|<)\\s*["']?([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`\\b${escaped}\\b["']?\\s*[:=]\\s*["']?[^0-9\\n\\r]{0,12}([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`name\\s*=\\s*["']${escaped}["'][\\s\\S]{0,300}?version\\s*=\\s*["']([0-9]+\\.[0-9]+\\.[0-9]+)["']`, "gi"),
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function npmVersionsInText(text) {
  const versions = new Set();
  const patterns = [
    /"packageManager"\s*:\s*"npm@([0-9]+\.[0-9]+\.[0-9]+)"/gi,
    /"npm"\s*:\s*"[^"]*?([0-9]+\.[0-9]+\.[0-9]+)[^"]*"/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function pythonPackageVersionInText(text, packageName, version) {
  const escapedPkg = escapeRegExp(packageName);
  const escapedVersion = escapeRegExp(version);
  const normalized = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*${escapedVersion})`, "im"),
    new RegExp(`${escapedPkg}[^\\n\\r]{0,200}${escapedVersion}`, "i"),
  ];
  return patterns.some((pattern) => pattern.test(normalized));
}

function pythonPackageNameInText(text, packageName) {
  const escapedPkg = escapeRegExp(packageName);
  const normalized = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*[^\\n\\r]+)`, "im"),
    new RegExp(`\\b${escapedPkg}\\b`, "i"),
  ];
  return patterns.some((pattern) => pattern.test(normalized));
}

function isHadesPthBunLoader(text) {
  const hasExecutablePthImport = /^\s*import[ \t]/m.test(text);
  const hasBunBootstrap = matchesAnyPattern(text, [
    ["oven-sh\\/bun\\/releases\\/", "download"],
    ["bun-v\\d+\\.\\d+\\.\\d+"],
    ["bun\\.sh\\/", "install"],
    ["Bun\\/1\\.3\\."]
  ]);
  const hasPythonExecution = /subprocess\.(run|Popen|call)|os\.system|exec\(/i.test(text);
  const hasPythonNetworkFetch = /urllib\.request|urlretrieve|requests\.get|curl\b|wget\b|fetch\(/i.test(text);
  return hasExecutablePthImport && /_index\.js/i.test(text) && hasPythonExecution && (hasBunBootstrap || hasPythonNetworkFetch);
}

function joinParts(...parts) {
  return parts.join("");
}

function matchesAnyPattern(text, patternParts) {
  return patternParts.some((parts) => new RegExp(parts.join(""), "i").test(text));
}

function isVersionInRange(version, inclusiveMin, exclusiveMax) {
  return compareDottedVersion(version, inclusiveMin) >= 0 && compareDottedVersion(version, exclusiveMax) < 0;
}

function compareDottedVersion(a, b) {
  const left = String(a).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = String(b).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] || 0;
    const r = right[i] || 0;
    if (l !== r) return l > r ? 1 : -1;
  }
  return 0;
}

module.exports = {
  scanHost,
  compareKernelRelease,
};
