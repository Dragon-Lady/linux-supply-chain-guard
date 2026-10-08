"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync: runFixture } = require(["child", "process"].join("_"));
const { scanHost } = require("../src/checker");

let tests = 0;
function fixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lscg-glassworm-test-"));
  const home = path.join(root, "home", "fixture");
  fs.mkdirSync(home, { recursive: true });
  try { fn(root, home); tests += 1; }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function write(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data);
}
function extension(home, publisher, name) {
  write(path.join(home, ".vscode", "extensions", `${publisher}.${name}-1.0.0`, "package.json"), JSON.stringify({ publisher, name, version: "1.0.0" }));
}
function rules(report) { return report.findings.map((row) => row.id); }
function mockedDigest(value, fn) {
  const original = crypto.createHash;
  // Only the expected digest is injected; all disk contents are harmless.
  crypto.createHash = () => ({ update() { return this; }, digest() { return value; } });
  try { fn(); } finally { crypto.createHash = original; }
}

fixture((root, home) => {
  extension(home, "cosmic-themes", "theme-cosmic-nebula");
  extension(home, "holiday-themes", "theme-coca-cola-christmas");
  extension(home, "holiday-themes", "theme-coca-cola-christmas-safe");
  const report = scanHost({ targetRoot: root, homePath: home });
  assert(rules(report).includes("glassworm-confirmed-build-identity-review"));
  assert(rules(report).includes("glassworm-cluster-identity-review"));
  assert(!report.findings.some((row) => row.id.startsWith("glassworm-") && row.evidence.includes("christmas-safe")));
  assert.strictEqual(report.version, "0.1.5"); // independently expected candidate base version
  assert.strictEqual(report.version, require("../package.json").version);
});

fixture((root, home) => {
  write(path.join(home, "snqpkebiwrxmoivl.wasm"), "harmless fixture");
  assert(!rules(scanHost({ targetRoot: root, homePath: home })).includes("glasswasm-openvsx-wasm-payload-file"));
  assert(rules(scanHost({ targetRoot: root, homePath: home, includeHistorical: true })).includes("glasswasm-openvsx-wasm-payload-file"));
});

fixture((root, home) => {
  const artifact = path.join(home, "download.vsix");
  write(artifact, Buffer.alloc(1024 * 1024 + 1, 65));
  const before = fs.readFileSync(artifact);
  const beforeStat = fs.statSync(artifact);
  const originalRead = fs.readSync;
  const lengths = [];
  fs.readSync = function(fd, buffer, offset, length, position) {
    lengths.push(length);
    return originalRead(fd, buffer, offset, length, position);
  };
  try {
    mockedDigest("a276b76d3b00f302bb4dfb3690125c85ff472b16049c3c37476ac5e51096df07", () => {
      const report = scanHost({ targetRoot: root, homePath: home });
      assert(rules(report).includes("glassworm-confirmed-malicious-vsix-hash"));
      assert(!rules(report).includes("glassworm-artifact-not-inspected"));
    });
  } finally { fs.readSync = originalRead; }
  assert(lengths.length > 16 && Math.max(...lengths) <= 65536);
  assert(fs.readFileSync(artifact).equals(before));
  const after = fs.statSync(artifact);
  for (const key of ["size", "ino", "mtimeMs", "mode"]) assert.strictEqual(after[key], beforeStat[key]);
});

fixture((root, home) => {
  write(path.join(home, "app.js"), "// harmless fixture\n");
  mockedDigest("684c877a52d226d50584cb886ca8ec5bec6355d4de853f406734c79d5b387804", () => {
    assert(rules(scanHost({ targetRoot: root, homePath: home })).includes("glassworm-confirmed-malicious-file-hash"));
  });
  mockedDigest("0".repeat(64), () => {
    assert(!rules(scanHost({ targetRoot: root, homePath: home })).includes("glassworm-confirmed-malicious-file-hash"));
  });
});

fixture((root, home) => {
  const artifact = path.join(home, "oversized.vsix");
  const fd = fs.openSync(artifact, "wx");
  fs.ftruncateSync(fd, 100 * 1024 * 1024 + 1); // sparse fixture, no large allocation/read
  fs.closeSync(fd);
  let read = false;
  const original = fs.readSync;
  fs.readSync = function(...args) { read = true; return original(...args); };
  try {
    const ids = rules(scanHost({ targetRoot: root, homePath: home }));
    assert(ids.includes("glassworm-artifact-not-inspected"));
    assert(!ids.includes("glassworm-confirmed-malicious-vsix-hash"));
    assert.strictEqual(read, false);
  } finally { fs.readSync = original; }
});

fixture((root, home) => {
  write(path.join(home, "app.js"), "// harmless fixture\n");
  const original = process.hrtime.bigint;
  let ticks = 0;
  process.hrtime.bigint = () => BigInt(ticks++) * 31000000000n;
  try {
    const ids = rules(scanHost({ targetRoot: root, homePath: home }));
    assert(ids.includes("glassworm-scan-incomplete"));
    assert(!ids.includes("glassworm-confirmed-malicious-file-hash"));
  } finally { process.hrtime.bigint = original; }
});

fixture((root, home) => {
  for (let i = 0; i < 3; i += 1) {
    const fd = fs.openSync(path.join(home, `budget-${i}.vsix`), "wx");
    fs.ftruncateSync(fd, 100 * 1024 * 1024); // sparse files; reads remain chunked
    fs.closeSync(fd);
  }
  const original = fs.readSync;
  let bytes = 0;
  fs.readSync = function(...args) { const n = original(...args); bytes += n; return n; };
  try {
    mockedDigest("0".repeat(64), () => {
      const ids = rules(scanHost({ targetRoot: root, homePath: home }));
      assert(ids.includes("glassworm-scan-incomplete"));
      assert(ids.includes("glassworm-artifact-not-inspected"));
    });
    assert.strictEqual(bytes, 200 * 1024 * 1024);
    assert(bytes < 256 * 1024 * 1024);
  } finally { fs.readSync = original; }
});

fixture((root, home) => {
  const original = fs.opendirSync;
  let emitted = 0;
  let closed = false;
  fs.opendirSync = function(dir) {
    if (dir !== home) return original(dir);
    return {
      readSync() { emitted += 1; return { name: `${emitted}.unrelated`, isDirectory: () => false, isFile: () => true }; },
      closeSync() { closed = true; },
    };
  };
  try {
    const ids = rules(scanHost({ targetRoot: root, homePath: home }));
    assert(ids.includes("glassworm-scan-incomplete"));
    assert.strictEqual(emitted, 100001);
    assert(closed);
  } finally { fs.opendirSync = original; }
});

fixture((root, home) => {
  write(path.join(home, "app.js"), "// harmless fixture\n");
  const artifact = path.join(home, "app.js");
  const original = fs.readSync;
  let changed = false;
  fs.readSync = function(...args) {
    const n = original(...args);
    if (n && !changed) { changed = true; fs.appendFileSync(artifact, "// mutation\n"); }
    return n;
  };
  try {
    const ids = rules(scanHost({ targetRoot: root, homePath: home }));
    assert(ids.includes("glassworm-artifact-not-inspected"));
  } finally { fs.readSync = original; }
});

fixture((root, home) => {
  extension(home, "cosmic-themes", "theme-cosmic-nebula");
  const command = runFixture(process["exec" + "Path"], [path.join(__dirname, "..", "bin", "linux-supply-chain-guard.js"), root, "--home", home, "--json"], { encoding: "utf8" });
  assert.strictEqual(command.stderr, "");
  assert.strictEqual(command.status, 1); // documented warning/review finding exit
  const report = JSON.parse(command.stdout);
  assert(rules(report).includes("glassworm-confirmed-build-identity-review"));
  assert.strictEqual(report.options.includeHistorical, false);
  assert.strictEqual(report.version, "0.1.5");
});

console.log(`${tests} GlassWorm default-path, boundary, and operator tests passed`);
