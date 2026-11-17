"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanSansar } = require("../src/sansar");
const { scanHost } = require("../src/checker");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sansar-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (relative, text = "inert fixture") => {
    const file = path.join(root, relative); fs.mkdirSync(path.dirname(file), {recursive:true});
    fs.writeFileSync(file, text); return file;
  };
  return { root, write, scan: options => scanSansar({ targetRoot: root, ...options }) };
}
const ids = report => report.findings.map(x => x.id);
test("absent paths, ordinary NVML and generic netns stay clear", t => {
  const {write,scan}=fixture(t);
  write("usr/lib/libnvidia-ml.so.1"); write("usr/src/linux/include/net/netns/test.h");
  write("etc/systemd/system/netns.service", "[Service]\nExecStart=/usr/bin/ip netns list\n");
  write("etc/initramfs-tools/hooks/legitimate", "# acpi_thermal_mgr is a research example\necho normal\n");
  assert.deepEqual(ids(scan()), []); assert.equal(scan().coverage.complete, true);
});
test("a single artifact requests review, separate categories increase priority", t => {
  const {write,scan}=fixture(t);
  write("opt/vadi_/sansar", "throw new Error('must not execute')");
  let report=scan(); assert(ids(report).includes("sansar-staged-tool"));
  assert(report.findings.every(x=>x.severity==="review"));
  write("opt/vadi_/nvml-hook/libnvidia-ml.so.1");
  report=scan(); assert(ids(report).includes("sansar-correlated-artifacts"));
  assert.equal(report.compromiseStatus,"unknown");
});
test("module and boot indicators are found without kernel execution", t => {
  const {root,write,scan}=fixture(t);
  fs.mkdirSync(path.join(root,"sys/module/acpi_thermal_mgr"),{recursive:true});
  fs.mkdirSync(path.join(root,"var/lib/dkms/acpi_thermal_mgr/0.1"),{recursive:true});
  write("etc/initramfs-tools/modules","acpi_thermal_mgr\n");
  write("etc/initramfs-tools/hooks/thermal", "copy_exec /opt/vadi_/acpi_thermal_mgr.ko\n");
  write("etc/modules-load.d/thermal.conf", "acpi_thermal_mgr\n");
  const report=scan();assert.equal(report.findings.filter(x=>x.id==="sansar-module-artifact").length,2);
  assert(ids(report).includes("sansar-boot-module-reference"));assert(ids(report).includes("sansar-boot-persistence-reference"));
});
test("service requires the reported executable and never returns secret values", t => {
  const {write,scan}=fixture(t);
  const p=write("etc/systemd/system/netns.service","[Service]\nEnvironment=PRIVATE_VALUE=synthetic-private-value\nExecStart=/opt/vadi_/netns\n");
  assert(ids(scan()).includes("sansar-backdoor-service-reference"));
  assert(!JSON.stringify(scan()).includes("synthetic-private-value"));
  fs.writeFileSync(p,"[Service]\n# ExecStart=/opt/vadi_/netns\nExecStart=/usr/bin/ip netns list\n");
  assert.deepEqual(ids(scan()),[]);
});
test("excluded and symlinked candidates are incomplete and never followed", t => {
  const {root,write,scan}=fixture(t);
  write("opt/vadi_/sansar");
  const excluded=scan({excludePaths:[path.join(root,"opt")]});
  assert.equal(excluded.coverage.complete,false);assert(!ids(excluded).includes("sansar-staged-tool"));
  fs.renameSync(path.join(root,"opt"),path.join(root,"other"));fs.symlinkSync("other",path.join(root,"opt"));
  const linked=scan();assert.equal(linked.coverage.complete,false);assert(!ids(linked).includes("sansar-staged-tool"));
  fs.mkdirSync(path.join(root,"etc/initramfs-tools/hooks"),{recursive:true});
  fs.symlinkSync(path.join(root,"other/vadi_/sansar"),path.join(root,"etc/initramfs-tools/hooks/link"));
  assert(scan().coverage.problems.some(x=>x.reason==="symlink-not-followed"));
});
test("oversized config, discovery limits and read failures remain incomplete", t => {
  const {write,scan}=fixture(t);
  write("etc/initramfs-tools/hooks/a", "acpi_thermal_mgr\n".repeat(5));
  write("etc/initramfs-tools/hooks/b", "normal");
  assert.equal(scan({limits:{fileBytes:16}}).coverage.complete,false);
  assert.equal(scan({limits:{entries:1}}).coverage.complete,false);
  const original=fs.openSync;
  fs.openSync=(file,...args)=>{if(String(file).endsWith("/a")){const err=Error("denied");err.code="EACCES";throw err;}return original(file,...args);};
  try {assert.equal(scan().coverage.complete,false);} finally {fs.openSync=original;}
});
test("default host scans include SANSAR and aggregate inspection gaps", t => {
  const {root,write}=fixture(t);
  const home=path.join(root,"home/fixture"); fs.mkdirSync(home,{recursive:true});
  write("opt/vadi_/sansar");
  let report=scanHost({targetRoot:root,homePath:home});
  assert(ids(report).includes("sansar-staged-tool"));assert.equal(report.sansar.compromiseStatus,"unknown");
  report=scanHost({targetRoot:root,homePath:home,excludePaths:[path.join(root,"opt")]});
  assert.equal(report.coverage.complete,false);assert(report.coverage.inspectionFailures.includes("sansar-coverage-incomplete"));
});
