"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanPhpReadiness, inspectProjectText, compareUpstream } = require("../src/php-readiness");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "php-readiness-"));
  const home = path.join(root, "accounts/operator");
  fs.mkdirSync(home, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const put = (relative, content) => {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    return file;
  };
  return { root, home, put, scan: options => scanPhpReadiness({ targetRoot: root, homePath: home, ...options }) };
}
const dpkg = (name, version, status = "install ok installed") =>
  "Package: " + name + "\nStatus: " + status + "\nVersion: " + version + "\n\n";

test("each confirmed branch distinguishes the last affected and first fixed upstream versions", () => {
  for (const [branch, lastAffected, fixed, later] of [["8.2", "8.2.34", "8.2.35", "8.2.36"],
    ["8.3", "8.3.35", "8.3.36", "8.3.37"], ["8.4", "8.4.26", "8.4.27", "8.4.28"],
    ["8.5", "8.5.11", "8.5.12", "8.5.13"]]) {
    assert.deepEqual(compareUpstream(lastAffected), { status: "below-fixed-upstream", version: lastAffected, branch, fixedVersion: fixed });
    assert.equal(compareUpstream(fixed).status, "at-or-above-fixed-upstream");
    // A numeric comparison is not a claim that a future release exists.
    assert.equal(compareUpstream(later).status, "at-or-above-fixed-upstream");
    assert.equal(compareUpstream(branch + ".9").status, "below-fixed-upstream");
    assert.equal(compareUpstream(branch + ".100").status, "at-or-above-fixed-upstream");
  }
});

test("non-final, ambiguous, unlisted and unsupported upstream versions are not cleared", () => {
  for (const version of [null, "8.5", "8.5.12RC1", "8.5.12-rc1", "8.5.12-dev", "08.5.12", "8.5.012", "8.5.12+vendor", "8.5.9007199254740992", "9.0.0", "8.6.0", "6.0.0"])
    assert.equal(compareUpstream(version).status, "unknown", String(version));
  for (const version of ["5.6.40", "7.4.33", "8.0.30", "8.1.34"])
    assert.equal(compareUpstream(version).status, "unsupported-upstream");
});

test("vendor revisions, including synthetic backports, retain unknown deployment patch status", t => {
  const f = fixture(t);
  // Synthetic vendor revisions exercise backport ambiguity; they are not
  // assertions that any distribution published these exact packages.
  f.put("var/lib/dpkg/status", dpkg("php8.3-fpm", "2:8.3.35-0vendor99")
    + dpkg("php8.4-cli", "8.4.27+dfsg1-1vendor1") + dpkg("libapache2-mod-php8.1", "8.1.2-99vendor1"));
  f.put("lib/apk/db/installed", "P:php85-fpm\nV:8.5.11-r99\n\nP:php85\nV:8.5.12-r0\n");
  const r = f.scan();
  assert.deepEqual(r.records.map(x => x.upstreamAssessment.status), ["below-fixed-upstream", "at-or-above-fixed-upstream", "unsupported-upstream", "below-fixed-upstream", "at-or-above-fixed-upstream"]);
  assert(r.records.every(x => x.patchStatus === "unknown" && x.upstreamAssessment.reason === "vendor-backport-status-unverified"));
  assert(r.findings.every(x => x.evidence.includes("vendor backport status unverified")));
  assert.equal(r.patchStatus, "unknown");
});

test("extensions, metapackages, inconsistent branches and prerelease packages cannot impersonate fixed runtimes", t => {
  const f = fixture(t);
  const unknown = [["php8.4-redis", "8.4.27"], ["php-cli", "8.4.27"], ["php8.4", "8.4.27"],
    ["php8.4-fpm", "8.5.12-1"], ["php8.5-cli", "8.5.12~rc1-1"], ["php8.5-cgi", "8.5.12RC1-1"]];
  f.put("var/lib/dpkg/status", unknown.map(([name, version]) => dpkg(name, version)).join(""));
  f.put("lib/apk/db/installed", "P:php85-pecl-redis\nV:8.5.12-r0\n\nP:php85-fpm\nV:8.5.12_rc1-r0\n\nP:php84\nV:8.5.12-r0\n");
  assert(f.scan().records.every(x => x.upstreamAssessment.status === "unknown"));
});

test("fixed declarations, stale tags and pinned digests do not verify deployed images", t => {
  const f = fixture(t);
  const dockerfile = "FROM php:8.5.11-fpm AS old\nFROM php:8.5.12-fpm-alpine3.24@sha256:" + "a".repeat(64)
    + " AS new\nFROM php:8.5.12-rc1-fpm AS prerelease\nFROM php:8.5.12-fpm-custom AS custom\nFROM php:8.5-fpm AS floating\nFROM php@sha256:" + "b".repeat(64);
  assert.deepEqual(inspectProjectText("Dockerfile", dockerfile).map(x => x.version), ["8.5.11", "8.5.12", null, null, null, null]);
  f.put("srv/app/Dockerfile", dockerfile);
  f.put("srv/app/composer.json", '{"config":{"platform":{"php":"8.5.12"}}}');
  const r = f.scan(), images = r.records.filter(x => x.kind === "container-declaration");
  // Identical unknown leads in one file are deduplicated by the inventory.
  assert.deepEqual(images.map(x => x.upstreamAssessment.status), ["below-fixed-upstream", "at-or-above-fixed-upstream", "unknown"]);
  assert(r.records.every(x => x.patchStatus === "unknown"));
  assert.equal(r.records.find(x => x.kind === "composer-declaration").upstreamAssessment.status, "unknown");
  assert.equal(r.patchStatus, "unknown");
  assert.equal(r.coverage.complete, true);
});

test("a fixed declaration cannot hide a simultaneous older branch or incomplete inspection", t => {
  const f = fixture(t);
  f.put("srv/new/Dockerfile", "FROM php:8.5.12-apache");
  f.put("srv/old/Dockerfile", "FROM php:8.2.34-fpm");
  f.put("srv/unresolved/compose.yaml", "services: {app: {image: php:8.5.12}}");
  const r = f.scan();
  assert(r.records.some(x => x.upstreamAssessment.status === "below-fixed-upstream"));
  assert(r.records.some(x => x.upstreamAssessment.status === "at-or-above-fixed-upstream"));
  assert.equal(r.coverage.complete, false);
  assert.equal(r.patchStatus, "unknown");
  assert(r.findings.some(x => x.id === "php-readiness-incomplete"));
});

test("editing a returned advisory snapshot cannot change future comparisons", t => {
  const f = fixture(t);
  f.scan().advisory.fixedVersions["8.5"] = "8.5.1";
  assert.equal(compareUpstream("8.5.11").status, "below-fixed-upstream");
});

test("inventories PHP branches and preserves complete distro revisions without declaring a fix", t => {
  const f = fixture(t);
  f.put("var/lib/dpkg/status", dpkg("php8.2-cli", "8.2.34-1+deb12u1") + dpkg("php8.3-fpm", "1:8.3.35-0ubuntu0.1")
    + dpkg("libapache2-mod-php8.4", "8.4.26-1", "hold ok installed") + dpkg("php8.3-cli", "8.3.35", "deinstall ok config-files")
    + dpkg("phpunit", "10.0.0") + dpkg("phpmyadmin", "5.0.0"));
  const result = f.scan();
  assert.deepEqual(result.records.map(x => x.version), ["8.2.34-1+deb12u1", "1:8.3.35-0ubuntu0.1", "8.4.26-1"]);
  assert(result.records.every(x => x.patchStatus === "unknown"));
  assert(result.findings.every(x => x.severity === "review"));
  assert.deepEqual(result.advisory.fixedVersions, { "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12" });
  assert(result.records.every(x => x.upstreamAssessment.status === "below-fixed-upstream"));
  assert.equal(result.patchStatus, "unknown");
});

test("Alpine package metadata is recognized without launching apk", t => {
  const f = fixture(t);
  f.put("lib/apk/db/installed", "P:php84\nV:8.4.26-r0\n\nP:php84-fpm\nV:8.4.26-r0\n\nP:unrelated\nV:1.0\n");
  const r = f.scan();
  assert.equal(r.packageInventory.apk, "read");
  assert.deepEqual(r.records.map(x => x.name), ["php84", "php84-fpm"]);
});

test("merged-/usr layout does not follow /lib or invent missing APK evidence", t => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.root, "usr/lib"), { recursive: true });
  fs.symlinkSync("usr/lib", path.join(f.root, "lib"));
  assert.equal(f.scan().coverage.complete, true);
});

test("malformed or partly configured package metadata is incomplete and never leaks fields", t => {
  const f = fixture(t);
  for (const text of ["broken", dpkg("php8.3-fpm", "PRIVATE VALUE"), dpkg("php8.3-fpm", "8.3.0", "install ok half-configured"),
    dpkg("php8.3-fpm", "8.3.0") + "Package: php8.2-cli\nPackage: php8.3-cli\n"]) {
    f.put("var/lib/dpkg/status", text);
    const r = f.scan();
    assert.equal(r.coverage.complete, false);
    assert(!JSON.stringify(r).includes("PRIVATE VALUE"));
  }
});

test("path hints, links, configuration and Apache modules do not imply an active runtime", t => {
  const f = fixture(t);
  f.put("usr/bin/php8.3", "do not execute");
  fs.symlinkSync("php8.3", path.join(f.root, "usr/bin/php"));
  f.put("usr/sbin/php-fpm8.3", "do not execute");
  f.put("etc/php/8.3/fpm/php.ini", "secret configuration value");
  f.put("etc/apache2/mods-available/php8.3.load", "secret module setting");
  const r = f.scan();
  assert.equal(r.records.length, 5);
  assert(r.records.some(x => x.kind === "binary-link"));
  assert(r.records.every(x => x.version === null));
  assert(!JSON.stringify(r).includes("secret"));
});

test("Composer requirements and platform overrides are declaration leads only", () => {
  for (const obj of [{ require: { php: "^8.3" } }, { "require-dev": { php: ">=8" } }, { config: { platform: { php: "8.5.99" } } }]) {
    const rows = inspectProjectText("composer.json", JSON.stringify(obj));
    assert.deepEqual(rows, [{ kind: "composer-declaration", version: null }]);
  }
  assert.equal(inspectProjectText("composer.lock", '{"platform":{"php":"^8.2"}}').length, 1);
  assert.deepEqual(inspectProjectText("composer.lock", '{"platform":[],"platform-dev":[]}'), []);
  assert.deepEqual(inspectProjectText("composer.json", '{"description":"php 8.3","require":{"unrelated/php":"8.3"}}'), []);
  assert.throws(() => inspectProjectText("composer.json", "[]"));
  assert.throws(() => inspectProjectText("composer.json", '{"require":"php"}'));
});

test("Docker stages and exact official image identities are recognized, never executed", () => {
  const rows = inspectProjectText("Dockerfile", "# FROM php:8.1\nFROM --platform=linux/amd64 docker.io/library/php:8.3.35-fpm AS runtime\n"
    + "FROM php:${PHP_VERSION}-cli AS tests\nFROM vendor/php:8.3.35\nFROM phpmyadmin:latest\nRUN echo php\n");
  assert.deepEqual(rows.map(x => x.version), ["8.3.35", null]);
  assert.equal(inspectProjectText("Containerfile", "FROM php@sha256:" + "a".repeat(64))[0].version, null);
  assert.throws(() => inspectProjectText("Dockerfile", "FROM ${BASE}"));
  assert.throws(() => inspectProjectText("Dockerfile", "RUN <<EOF\nFROM php:8.0.0\nEOF"));
});

test("Compose reads service images, ignoring comments, nested arguments and block scalar text", () => {
  const text = "services:\n  app:\n    image: 'php:8.3.35-fpm' # tagged\n    command: |\n      image: php:8.0.0\n"
    + "    build:\n      args:\n        image: php:8.1.0\n  worker:\n    image: php:${PHP_VERSION}-cli\n"
    + "  unrelated:\n    image: custom/php:8.0.0\n# image: php:8.0.0\n";
  assert.deepEqual(inspectProjectText("compose.yaml", text).map(x => x.version), ["8.3.35", null]);
});

test("unsupported Compose indirection stays incomplete instead of silently resolving it", () => {
  for (const text of ["services: {app: {image: php:8.3}}", "services:\n  app: {image: php:8.3}", "include: other.yml", "services:\n  app:\n    <<: *default",
    "services:\n  app:\n    image: ${IMAGE}", "services:\n  app: &default\n    image: php:8.3"])
    assert.throws(() => inspectProjectText("compose.yml", text));
});

test("project declarations are found in opted-in home and deployment roots", t => {
  const f = fixture(t);
  f.put("accounts/operator/.cache/project/composer.json", '{"require":{"php":"^8.3"}}');
  f.put("srv/app/Dockerfile", "FROM php:8.3.35-fpm");
  f.put("var/www/app/compose.yml", "services:\n  app:\n    image: php:8.4.26-apache");
  f.put("opt/app/composer.lock", '{"platform":{"php":">=8"}}');
  f.put("srv/app/vendor/example/composer.json", '{"require":{"php":"^8.2"}}');
  const result = f.scan();
  assert.equal(result.records.length, 4);
  assert.equal(result.coverage.complete, true);
  assert.equal(result.presence, "observed");
});

test("empty inventory remains unknown, with explicit scope and absence limitations", t => {
  const f = fixture(t), r = f.scan();
  assert.equal(r.presence, "not-observed");
  assert.equal(r.patchStatus, "unknown");
  assert.equal(r.coverage.complete, true);
  assert.match(r.coverage.limitations.join(" "), /absence is not proof/);
  assert.equal(r.advisory.checkedOn, "2026-10-23");
});

test("symlinked candidates and parent directories never import outside-root declarations", t => {
  const f = fixture(t);
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "php-outside-"));
  t.after(() => fs.rmSync(external, { recursive: true, force: true }));
  fs.writeFileSync(path.join(external, "composer.json"), '{"require":{"php":"^8.3"}}');
  fs.symlinkSync(path.join(external, "composer.json"), path.join(f.home, "composer.json"));
  fs.symlinkSync(external, path.join(f.root, "srv"));
  const r = f.scan();
  assert.equal(r.records.length, 0);
  assert.equal(r.coverage.complete, false);
  assert(!JSON.stringify(r).includes(external));
});

test("explicit symlinked roots retain package and selected-home inventory", t => {
  const f = fixture(t);
  f.put("var/lib/dpkg/status", dpkg("php8.3-fpm", "8.3.35-1"));
  f.put("accounts/operator/app/composer.json", '{"require":{"php":"^8.3"}}');
  const alias = path.join(f.root, "selected-root");
  fs.symlinkSync(f.root, alias);
  const r = f.scan({ targetRoot: alias, homePath: path.join(alias, "accounts/operator") });
  assert.equal(r.coverage.complete, true);
  assert.equal(r.packageInventory.dpkg, "read");
  assert.deepEqual(r.records, f.scan().records);
});

test("symlinked roots still enforce exclusions and reject discovered links", t => {
  const f = fixture(t), outside = fixture(t);
  f.put("accounts/operator/private/composer.json", '{"require":{"php":"^8.3"}}');
  outside.put("app/composer.json", '{"require":{"php":"^8.3"}}');
  fs.symlinkSync(path.join(outside.root, "app"), path.join(f.root, "srv"));
  const alias = path.join(f.root, "selected-root");
  fs.symlinkSync(f.root, alias);
  const r = f.scan({ targetRoot: alias, homePath: path.join(alias, "accounts/operator"),
    excludePaths: [path.join(alias, "accounts/operator/private")] });
  assert.deepEqual(r.records, []);
  assert.equal(r.coverage.complete, false);
  assert(r.coverage.problems.some(x => x.reason === "excluded"));
  assert(r.coverage.problems.some(x => x.path === "/srv" && x.reason === "not-directory"));
  assert(!JSON.stringify(r).includes(outside.root));
});

test("broken roots and links to regular files remain invalid", t => {
  const f = fixture(t);
  const file = f.put("ordinary.txt", "ordinary fixture");
  for (const [name, destination] of [["broken-root", path.join(f.root, "absent")], ["file-root", file]]) {
    const alias = path.join(f.root, name);
    fs.symlinkSync(destination, alias);
    const r = f.scan({ targetRoot: alias, homePath: undefined });
    assert.deepEqual(r.records, []);
    assert.equal(r.coverage.complete, false);
    assert(r.coverage.problems.some(x => x.reason === "invalid-root"));
  }
});

test("exclusions are enforced before contents are read", t => {
  const f = fixture(t);
  f.put("srv/private/composer.json", '{"require":{"php":"^8.3"}}');
  const r = f.scan({ excludePaths: [path.join(f.root, "srv/private")] });
  assert.equal(r.records.length, 0);
  assert.equal(r.coverage.complete, false);
  assert(r.coverage.problems.some(x => x.reason === "excluded"));
});

test("size, total-byte, candidate, entry, depth and record budgets are explicit", t => {
  const f = fixture(t);
  f.put("srv/a/b/c/composer.json", '{"require":{"php":"^8.3"}}');
  f.put("srv/app/Dockerfile", "FROM php:8.3.35-fpm");
  for (const [limits, reason] of [[{ fileBytes: 5 }, "file-size-limit"], [{ bytes: 5 }, "byte-limit"], [{ files: 1 }, "file-limit"],
    [{ entries: 1 }, "entry-limit"], [{ depth: 1 }, "depth-limit"], [{ records: 1 }, "record-limit"]]) {
    const r = f.scan({ limits });
    assert.equal(r.coverage.complete, false, reason);
    assert(r.coverage.problems.some(x => x.reason === reason), JSON.stringify(r.coverage.problems));
  }
});

test("time budget cannot yield a completed empty inventory", t => {
  const f = fixture(t), now = Date.now;
  let clock = 0;
  Date.now = () => clock += 10;
  try {
    const r = f.scan({ limits: { milliseconds: 1 } });
    assert.equal(r.coverage.complete, false);
    assert(r.coverage.problems.some(x => x.reason === "time-limit"));
  } finally { Date.now = now; }
});

test("read and listing failures are incomplete without error text disclosure", t => {
  const f = fixture(t);
  f.put("srv/app/composer.json", '{"require":{"php":"^8.3"}}');
  const original = fs.openSync;
  fs.openSync = (file, ...args) => {
    if (path.basename(file) === "composer.json") throw new Error("private error detail");
    return original(file, ...args);
  };
  try {
    const r = f.scan();
    assert.equal(r.coverage.complete, false);
    assert(!JSON.stringify(r).includes("private error detail"));
  } finally { fs.openSync = original; }
  assert.equal(f.scan().coverage.complete, true, "failure state resets");
  const openDirectory = fs.opendirSync;
  fs.opendirSync = input => {
    if (input === path.join(f.root, "srv")) throw new Error("private listing detail");
    return openDirectory(input);
  };
  try {
    const r = f.scan();
    assert.equal(r.coverage.complete, false);
    assert(r.coverage.problems.some(x => x.reason === "unlistable-directory"));
    assert(!JSON.stringify(r).includes("private listing detail"));
  } finally { fs.opendirSync = openDirectory; }
});

test("replacement during a read is discarded", t => {
  const f = fixture(t);
  const file = f.put("srv/app/composer.json", '{"require":{"php":"^8.3"}}');
  const original = fs.readSync;
  let replaced = false;
  fs.readSync = (...args) => {
    const n = original(...args);
    if (!replaced) { replaced = true; fs.renameSync(file, file + ".old"); fs.writeFileSync(file, "{}"); }
    return n;
  };
  try {
    const r = f.scan();
    assert.equal(r.records.length, 0);
    assert.equal(r.coverage.complete, false);
  } finally { fs.readSync = original; }
});

test("scanner does not execute PHP, package managers, configuration or network calls", t => {
  const f = fixture(t);
  const binary = f.put("usr/bin/php", "inert fixture that must never execute");
  fs.chmodSync(binary, 0o700);
  const file = f.put("srv/app/composer.json", '{"require":{"php":"^8.3"},"scripts":{"post-install-cmd":"fixture command"}}');
  const before = fs.readFileSync(file);
  const Module = require("node:module");
  const originalLoad = Module._load, originalFetch = global.fetch;
  const resolved = require.resolve("../src/php-readiness");
  const cached = require.cache[resolved];
  delete require.cache[resolved];
  const allowed = new Set(["../src/php-readiness", "node:fs", "node:path", "../data/php-readiness.json"]);
  Module._load = (request, ...args) => {
    if (!allowed.has(request)) throw new Error("unexpected runtime dependency");
    return originalLoad.call(Module, request, ...args);
  };
  global.fetch = () => { throw new Error("unexpected network action"); };
  try {
    const isolated = require("../src/php-readiness");
    assert.equal(isolated.scanPhpReadiness({ targetRoot: f.root, homePath: f.home }).records.length, 2);
  } finally {
    Module._load = originalLoad;
    global.fetch = originalFetch;
    require.cache[resolved] = cached;
  }
  assert.deepEqual(fs.readFileSync(file), before);
});

test("October 23 advisory does not inherit the earlier CVEs' fixed-version table", () => {
 const advisory=require("../data/php-readiness.json");
 assert.equal(advisory.additionalAdvisory.cve,"CVE-2026-115560");
 assert.equal(advisory.additionalAdvisory.fixedVersions,null);
 assert.match(advisory.note,/covers only CVE-2026-109618 and CVE-2026-109619/);
});
