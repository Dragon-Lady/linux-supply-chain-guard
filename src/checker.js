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

const KNOWN_DPRK_NPM_PACKAGES = [
  "terminal-logger-utils",
  "pretty-logger-utils",
  "ts-logger-pack",
  "pinno-loggers",
];

const DPRK_NPM_TEXT_INDICATORS = [
  "utils.cjs",
  "/api/validate/keyboard-events",
  "pwdKeyString",
  "Telegram Desktop",
];

const DEPENDENCY_FILE_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

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
  checkDprkNpmRat(findings, targetRoot, homePath);
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  scanHost,
  compareKernelRelease,
};
