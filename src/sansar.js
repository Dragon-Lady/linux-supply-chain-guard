"use strict";

// Inspect artifacts as data only, through the existing descriptor-anchored reader.
const path = require("node:path");
const { createReader } = require("./web-files");
const SOURCE = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware";
const GUIDANCE = "Preserve evidence and verify these artifacts from a trusted environment. Review Ray job-agent access, kernel/DKMS and initramfs changes, and NVML package integrity. A marker is not proof of malware execution or attribution; this check does not remediate or contact external services.";

function scanSansar(options = {}) {
  const reader = createReader({ ...options, limits: { entries: 5000, files: 500,
    bytes: 8 * 1024 * 1024, fileBytes: 256 * 1024, depth: 8, milliseconds: 2000,
    ...options.limits } });
  const findings = [], categories = new Set();
  const add = (file, id, title, category) => {
    findings.push({ id: "sansar-" + id, severity: "review", title,
      evidence: reader.display(file), guidance: GUIDANCE });
    categories.add(category);
  };
  function present(relative, kind) {
    const file = reader.mapped(relative), stat = reader.stat(file);
    if (!stat) return null;
    if (stat.isSymbolicLink()) { reader.gap(file, "symlink-not-followed"); return null; }
    if (!(kind === "directory" ? stat.isDirectory() : stat.isFile())) {
      reader.gap(file, "unexpected-file-type"); return null;
    }
    return file;
  }
  function readText(file) {
    const result = reader.read(file);
    if (!result) return null;
    // Config text is inspected, never returned as evidence (it may hold secrets).
    if (result.data.includes(0)) { reader.gap(file, "unsupported-config-encoding"); return null; }
    return result.data.toString("utf8").split(/\r?\n/)
      .filter(line => !/^\s*[#;]/.test(line)).join("\n");
  }
  try {
    const staging = present("/opt/vadi_", "directory");
    if (staging) add(staging, "staging-directory", "The reported SANSAR staging directory exists; review its origin.", "staging");
    for (const name of ["sansar", "kurt", "tilki", "netns"]) {
      const file = present("/opt/vadi_/" + name, "file");
      if (file) add(file, "staged-tool", "A reported toolkit filename occurs inside the SANSAR staging directory; identity is unverified.", "staging");
    }
    const wrapper = present("/opt/vadi_/nvml-hook/libnvidia-ml.so.1", "file");
    if (wrapper) add(wrapper, "nvml-wrapper-path", "An NVML library occurs at the reported toolkit wrapper path; verify its contents and provenance.", "nvml");
    for (const relative of ["/sys/module/acpi_thermal_mgr", "/var/lib/dkms/acpi_thermal_mgr"]) {
      const file = present(relative, "directory");
      if (file) add(file, "module-artifact", "A module or DKMS directory uses the reported acpi_thermal_mgr rootkit name; identity is unverified.", "module");
    }
    const modules = present("/etc/initramfs-tools/modules", "file");
    if (modules && /(?:^|\n)\s*acpi_thermal_mgr(?:\s|$)/.test(readText(modules) || ""))
      add(modules, "boot-module-reference", "The initramfs module list names the reported rootkit module.", "module");
    for (const relative of ["/etc/initramfs-tools/hooks", "/etc/initramfs-tools/scripts/init-top", "/etc/modules-load.d"]) {
      reader.walk(reader.mapped(relative), file => {
        const text = readText(file);
        if (text !== null && /\bacpi_thermal_mgr(?:\.ko)?\b|\/opt\/vadi_(?:\/|\b)/.test(text))
          add(file, "boot-persistence-reference", "Boot configuration references reported SANSAR persistence markers; review the configuration.", "boot");
      });
    }
    for (const relative of ["/etc/systemd/system/netns.service", "/usr/lib/systemd/system/netns.service"]) {
      const file = present(relative, "file");
      if (!file) continue;
      const text = readText(file);
      if (text !== null && /^\s*ExecStart\s*=.*\/opt\/vadi_\/netns(?:\s|["']|$)/m.test(text))
        add(file, "backdoor-service-reference", "A netns service launches the reported staged backdoor path; review before execution.", "service");
    }
    if (categories.size >= 2) findings.push({ id: "sansar-correlated-artifacts", severity: "warning",
      title: "Multiple SANSAR artifact categories were found; prioritize incident review.",
      evidence: [...categories].sort().join(", "), guidance: GUIDANCE });
    if (reader.problemCount) findings.push({ id: "sansar-coverage-incomplete", severity: "warning",
      title: "Some selected SANSAR artifact locations could not be inspected.",
      evidence: reader.problems.map(p => p.path + ": " + p.reason).join("; "),
      guidance: "Review the reported gaps from a trusted environment. A negative result is incomplete; no files were changed." });
    return { findings, advisory: { checkedOn: "2026-11-17", source: SOURCE }, compromiseStatus: "unknown",
      coverage: { complete: reader.problemCount === 0, scope: "reported staging, module, DKMS, initramfs configuration and netns service locations only; no memory, boot-image, network or arbitrary binary inspection",
        problems: reader.problems, problemCount: reader.problemCount } };
  } finally { reader.close(); }
}
module.exports = { scanSansar };
