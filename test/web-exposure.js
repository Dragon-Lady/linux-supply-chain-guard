"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { scanWebExposure, composeServices, portBinding } = require("../src/web-exposure");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "web-review-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const put = (relative, data = "", mode = 0o600) => {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, data, { mode });
    return file;
  };
  return { root, put, scan: options => scanWebExposure({ targetRoot: root, ...options }) };
}
const ids = r => r.findings.map(x => x.id);
function baseline(f, webroot) {
  const r = f.scan({ webroots: [webroot] });
  assert.equal(r.manifest.complete, true);
  return f.put("trusted-baseline.json", JSON.stringify({ webExposure: r }));
}
function compose(image, lines) {
  return `services:\n  example:\n    image: ${image}\n${lines.map(x => "    " + x).join("\n")}\n`;
}

test("missing optional paths remain complete, with unknown exposure and no clean-site claim", t => {
  const r = fixture(t).scan();
  assert.equal(r.coverage.complete, true);
  assert.deepEqual(r.findings, []);
  assert.equal(r.runtimeExposure, "unknown");
  assert.equal(r.comparison, "not-requested");
});
test("Webmin settings respect comments, last assignment, IPv6 and secret redaction", t => {
  const f = fixture(t);
  f.put("etc/webmin/miniserv.conf", "# bind=0.0.0.0\nbind=0.0.0.0\nbind=127.0.0.1\nssl=1\npassword=PRIVATE_SENTINEL\n");
  assert.deepEqual(ids(f.scan()), []);
  f.put("etc/webmin/miniserv.conf", "bind=::\nssl=0\npassword=PRIVATE_SENTINEL\n");
  const r = f.scan();
  assert(ids(r).includes("web-panel-nonloopback-bind"));
  assert(ids(r).includes("web-panel-cleartext"));
  assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
  f.put("etc/usermin/miniserv.conf", "bind=not-resolved.example\n");
  assert.equal(f.scan().coverage.complete, false);
});
test("Cockpit listener resets are respected within the file and other sections ignored", t => {
  const f = fixture(t);
  f.put("etc/systemd/system/cockpit.socket.d/listen.conf", "[Unit]\nListenStream=9090\n[Socket]\nListenStream=9090\nListenStream=\nListenStream=[::1]:9090\n");
  assert.deepEqual(ids(f.scan()), []);
  f.put("etc/systemd/system/cockpit.socket.d/listen.conf", "[Socket]\nListenStream=\nListenStream=0.0.0.0:9090\n");
  assert(ids(f.scan()).includes("web-panel-nonloopback-bind"));
});
test("Redis explicit risks are reported without assuming absent authentication or exposing secrets", t => {
  const f = fixture(t);
  f.put("etc/redis/redis.conf", 'bind 127.0.0.1 -::1\nprotected-mode yes\nrequirepass "PRIVATE_SENTINEL # in quoted value"\n');
  assert.deepEqual(ids(f.scan()), []);
  f.put("etc/redis/redis.conf", "bind 0.0.0.0\nprotected-mode no\nrequirepass PRIVATE_SENTINEL\n");
  const r = f.scan();
  assert(ids(r).includes("web-store-nonloopback-bind"));
  assert(ids(r).includes("web-store-redis-protection-disabled"));
  assert(!ids(r).includes("web-store-redis-passwordless-declaration"));
  assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
});
test("Redis ACL and include files require separate review rather than a clean verdict", t => {
  const f = fixture(t);
  f.put("etc/redis.conf", 'user default on nopass ~* +@all\nrequirepass ""\naclfile /private/acl\ninclude /private/config\n');
  const r = f.scan();
  assert(ids(r).includes("web-store-redis-passwordless-declaration"));
  assert(ids(r).includes("web-store-redis-empty-password"));
  assert.equal(r.coverage.complete, false);
  assert(!JSON.stringify(r).includes("/private/"));
});
test("Memcached distinguishes explicit public/UDP settings, loopback, sockets and unsupported formats", t => {
  const f = fixture(t);
  f.put("etc/memcached.conf", "-l 127.0.0.1,::1\n-U 0\n-m 64\n");
  assert.deepEqual(ids(f.scan()), []);
  f.put("etc/memcached.conf", "-l 0.0.0.0\n-U 11211\n-S\n");
  assert(ids(f.scan()).includes("web-store-nonloopback-bind"));
  assert(ids(f.scan()).includes("web-store-memcached-udp"));
  f.put("etc/memcached.conf", "-l 0.0.0.0\n-s /run/private.sock\n");
  assert.deepEqual(ids(f.scan()), []);
  f.put("etc/memcached.conf", 'OPTIONS="-l 0.0.0.0"\n');
  assert.equal(f.scan().coverage.complete, false);
});
test("PHP session handlers are configuration leads, not proof that Redis or Memcached is unauthenticated", t => {
  const f = fixture(t);
  f.put("etc/php/8.3/fpm/php.ini", 'session.save_handler=redis\nsession.save_path="tcp://127.0.0.1:6379?auth=PRIVATE_SENTINEL"\n');
  const r = f.scan();
  assert(ids(r).includes("web-session-network-store"));
  assert.equal(r.coverage.complete, true);
  assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
  assert(!JSON.stringify(r).includes("6379"));
});
test("PHP file sessions check directory modes without opening session contents", t => {
  const f = fixture(t);
  f.put("sessions/private-session", "PRIVATE_SESSION_DATA");
  fs.chmodSync(path.join(f.root, "sessions"), 0o777);
  f.put("etc/php.ini", 'session.save_handler=files\nsession.save_path="2;0600;/sessions"\n');
  const original = fs.openSync;
  fs.openSync = (file, ...args) => {
    assert(!String(file).endsWith("/private-session"), "session contents must never be opened");
    return original(file, ...args);
  };
  let r;
  try { r = f.scan(); } finally { fs.openSync = original; }
  assert(ids(r).includes("web-session-directory-readable"));
  assert(ids(r).includes("web-session-directory-writable"));
  assert(!JSON.stringify(r).includes("PRIVATE_SESSION_DATA"));
  fs.chmodSync(path.join(f.root, "sessions"), 0o700);
  assert.deepEqual(ids(f.scan()), []);
});
test("PHP conditional sections do not mask risky global session settings", t => {
  const f = fixture(t);
  f.put("etc/php.ini", "[Session]\nsession.save_handler=memcached\n[HOST=localhost]\nsession.save_handler=files\n");
  assert(ids(f.scan()).includes("web-session-network-store"));
});
test("missing or linked PHP session directories are incomplete without reading link targets", t => {
  const f = fixture(t);
  f.put("etc/php.ini", 'session.save_path="/absent"\n');
  assert.equal(f.scan().coverage.complete, false);
  fs.symlinkSync(os.tmpdir(), path.join(f.root, "absent"));
  assert.equal(f.scan().coverage.complete, false);
});
test("Compose published ports distinguish loopback, implicit all-address binds and expose-only", t => {
  const f = fixture(t);
  for (const value of ['"127.0.0.1:8080:80"', '"[::1]:8080:80"']) {
    f.put("srv/app/compose.yml", compose("adminer:latest", ["ports:", "  - " + value]));
    assert.deepEqual(ids(f.scan()), []);
  }
  for (const value of ['"8080:80"', '"80"', '"0.0.0.0:8080:80"', '"[::]:8080:80"']) {
    f.put("srv/app/compose.yml", compose("docker.io/library/phpmyadmin:5", ["ports:", "  - " + value]));
    const r = f.scan();
    assert.equal(r.coverage.complete, true, value);
    assert(ids(r).includes("web-panel-published-port"), value);
  }
  f.put("srv/app/compose.yml", compose("adminer", ["expose:", '  - "80"']));
  assert.deepEqual(ids(f.scan()), []);
});
test("Compose cache/host declarations and exact image identities are separate review leads", t => {
  const f = fixture(t);
  f.put("opt/app/compose.yml", compose("redis:7", ["ports:", '  - "6379:6379"']));
  assert(ids(f.scan()).includes("web-store-published-port"));
  f.put("opt/app/compose.yml", compose("portainer/portainer-ce:latest", ["network_mode: host"]));
  assert(ids(f.scan()).includes("web-compose-host-network"));
  for (const image of ["example/adminer", "adminer-malicious", "registry.example/redis"]) {
    f.put("opt/app/compose.yml", compose(image, ["ports:", '  - "8080:80"']));
    assert.deepEqual(ids(f.scan()), []);
  }
});
test("Compose scripts and comments are not interpreted as service declarations", t => {
  const f = fixture(t);
  f.put("srv/app/compose.yml", 'services:\n  web:\n    image: ordinary\n    command: |\n      services:\n        secret:\n          image: adminer\n          ports:\n            - "8080:80"\n# image: adminer\n');
  assert.deepEqual(ids(f.scan()), []);
});
test("unsupported Compose includes, aliases, flows, long ports, variables and duplicates are incomplete", t => {
  const f = fixture(t);
  for (const text of ["include: other.yml", "services: {web: {image: adminer}}", "services:\n  web: &defaults\n",
    compose("adminer", ["ports:", "  - target: 80", "    published: 8080"]), compose("${IMAGE}", []),
    compose("adminer", ["ports:", '  - "${PORT}:80"']), compose("adminer", ["image: redis"]),
    compose("{name: adminer}", []), compose("[]", []), compose("adminer", ["network_mode: {value: host}"]),
    "services:\n  web:\n    <<: *defaults\n"]) {
    f.put("srv/app/compose.yml", text);
    assert.equal(f.scan().coverage.complete, false, text);
  }
});
test("explicit Compose paths respect selected target boundaries and missing inputs", t => {
  const f = fixture(t);
  const file = f.put("custom/stack.yml", compose("adminer", ["ports:", '  - "8080:80"']));
  assert(ids(f.scan({ webCompose: [file] })).includes("web-panel-published-port"));
  assert.equal(f.scan({ webCompose: [path.join(f.root, "missing.yml")] }).coverage.complete, false);
  assert.equal(f.scan({ webCompose: [path.join(f.root, "..", "outside.yml")] }).coverage.complete, false);
});
test("webroot manifests hash bytes and permissions without printing content or trusting a first snapshot", t => {
  const f = fixture(t);
  const content = Buffer.from([0, 255, 1, 2]);
  f.put("site/index.bin", content, 0o640);
  const r = f.scan({ webroots: [path.join(f.root, "site")] });
  assert.equal(r.manifest.complete, true);
  assert.deepEqual(r.manifest.entries, [{ root: "/site", path: "index.bin", sha256: crypto.createHash("sha256").update(content).digest("hex"), size: 4, mode: 0o640 }]);
  assert(ids(r).includes("webroot-baseline-needed"));
  assert.equal(r.comparison, "not-requested");
});
test("baseline comparison finds added, removed, same-size changed and permission-changed files", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/index.php", "versionA"); f.put("site/remove.txt", "old"); f.put("site/mode.txt", "mode");
  const saved = baseline(f, root);
  assert.equal(f.scan({ webroots: [root], webBaseline: saved }).comparison, "matched");
  f.put("site/index.php", "versionB"); f.put("site/uploads/new.php", "new");
  fs.unlinkSync(path.join(root, "remove.txt")); fs.chmodSync(path.join(root, "mode.txt"), 0o644);
  const r = f.scan({ webroots: [root], webBaseline: saved });
  assert.equal(r.comparison, "changed");
  for (const kind of ["added", "removed", "content-changed", "permissions-changed"]) assert(ids(r).includes("webroot-" + kind));
  assert(!r.findings.some(x => x.severity === "critical"));
});
test("webroot hashing does not silently omit dependencies, hidden files or build output", t => {
  const f = fixture(t);
  for (const file of ["site/.htaccess", "site/.user.ini", "site/vendor/library.php", "site/dist/app.js"]) f.put(file, "fixture");
  const r = f.scan({ webroots: [path.join(f.root, "site")] });
  assert.equal(r.manifest.entries.length, 4);
});
test("malformed, duplicate, wrong-root, incomplete and traversing baselines are rejected", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/index.php", "known");
  const good = f.scan({ webroots: [root] }).manifest;
  const variants = ["broken", { ...good, complete: false }, { ...good, roots: ["/elsewhere"] },
    { ...good, entries: [good.entries[0], good.entries[0]] },
    { ...good, entries: [{ ...good.entries[0], path: "../outside" }] },
    { ...good, entries: [{ ...good.entries[0], sha256: "bad" }] },
    { ...good, entries: [{ ...good.entries[0], sha256: [good.entries[0].sha256] }] }];
  for (const item of variants) {
    const saved = f.put("baseline.json", typeof item === "string" ? item : JSON.stringify(item));
    const r = f.scan({ webroots: [root], webBaseline: saved });
    assert.equal(r.comparison, "incomplete");
    assert.equal(r.coverage.complete, false);
    assert(!ids(r).includes("webroot-removed"));
  }
});
test("incomplete webroot traversal cannot invent removals or emit a usable baseline", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/private/index.php", "known");
  const saved = baseline(f, root);
  const r = f.scan({ webroots: [root], webBaseline: saved, excludePaths: [path.join(root, "private")] });
  assert.equal(r.manifest.complete, false);
  assert.equal(r.comparison, "incomplete");
  assert(!ids(r).includes("webroot-removed"));
});
test("missing webroots and baselines are incomplete; invalid scope is a usage error", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  assert.equal(f.scan({ webroots: [root] }).manifest.complete, false);
  f.put("site/index.php", "known");
  assert.equal(f.scan({ webroots: [root], webBaseline: path.join(f.root, "absent") }).comparison, "incomplete");
  assert.throws(() => f.scan({ webBaseline: "file" }));
  assert.throws(() => f.scan({ webroots: [os.tmpdir()] }));
  assert.throws(() => f.scan({ webroots: [root], webBaseline: path.join(root, "baseline.json") }));
});
test("baseline comparison can succeed even when an unrelated config needs review", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/index.php", "known");
  const saved = baseline(f, root);
  f.put("etc/redis.conf", "include /private/redis.conf\n");
  const r = f.scan({ webroots: [root], webBaseline: saved });
  assert.equal(r.comparison, "matched");
  assert.equal(r.manifest.complete, true);
  assert.equal(r.coverage.complete, false);
});
test("discovered file/directory symlinks and linked baselines are not followed", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("outside/private", "SECRET"); f.put("site/index.php", "known");
  const saved = baseline(f, root);
  fs.symlinkSync(path.join(f.root, "outside"), path.join(root, "linked"));
  fs.symlinkSync(path.join(f.root, "outside/private"), path.join(root, "file"));
  const r = f.scan({ webroots: [root], webBaseline: saved });
  assert.equal(r.comparison, "incomplete");
  assert.equal(r.manifest.entries.length, 1);
  assert(!JSON.stringify(r).includes("SECRET"));
  fs.symlinkSync(saved, path.join(f.root, "baseline-link"));
  assert.equal(f.scan({ webroots: [root], webBaseline: path.join(f.root, "baseline-link") }).comparison, "incomplete");
});
test("explicit root alias works while linked config parents remain blocked", t => {
  const f = fixture(t);
  f.put("etc/redis.conf", "protected-mode no\n");
  const alias = path.join(f.root, "alias"); fs.symlinkSync(f.root, alias);
  assert(ids(scanWebExposure({ targetRoot: alias })).includes("web-store-redis-protection-disabled"));
  fs.mkdirSync(path.join(f.root, "alternative"));
  fs.symlinkSync(path.join(f.root, "alternative"), path.join(f.root, "etc/redis"));
  assert.equal(f.scan().coverage.complete, false);
});
test("descriptor anchoring prevents a replaced config ancestor redirecting reads", t => {
  const f = fixture(t);
  f.put("etc/redis/redis.conf", "bind 127.0.0.1\nprotected-mode yes\n");
  f.put("elsewhere/redis.conf", "bind 0.0.0.0\nprotected-mode no\n");
  const original = fs.openSync;
  let switched = false;
  fs.openSync = (file, ...args) => {
    if (!switched && String(file).endsWith("/redis.conf")) {
      switched = true;
      fs.renameSync(path.join(f.root, "etc/redis"), path.join(f.root, "original"));
      fs.symlinkSync(path.join(f.root, "elsewhere"), path.join(f.root, "etc/redis"));
    }
    return original(file, ...args);
  };
  let r;
  try { r = f.scan(); } finally { fs.openSync = original; }
  assert.equal(switched, true);
  assert(!ids(r).includes("web-store-redis-protection-disabled"));
});
test("changed file identities/content are incomplete rather than trusted hashes", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/file.txt", "initial");
  const original = fs.readSync;
  let changed = false;
  fs.readSync = (fd, ...args) => {
    const count = original(fd, ...args);
    if (!changed) { changed = true; f.put("site/file.txt", "longer replacement"); }
    return count;
  };
  let r;
  try { r = f.scan({ webroots: [root] }); } finally { fs.readSync = original; }
  assert.equal(r.manifest.complete, false);
  assert.equal(r.manifest.entries.length, 0);
});
test("unreadable configs and webroot files report sanitized gaps", { skip: !process.getuid || process.getuid() === 0 }, t => {
  const f = fixture(t);
  const config = f.put("etc/redis.conf", "PRIVATE_SENTINEL");
  const file = f.put("site/private.txt", "PRIVATE_SENTINEL");
  fs.chmodSync(config, 0); fs.chmodSync(file, 0);
  const r = f.scan({ webroots: [path.join(f.root, "site")] });
  assert.equal(r.coverage.complete, false);
  assert.equal(r.manifest.complete, false);
  assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
});
for (const limit of ["entries", "files", "bytes", "fileBytes", "depth", "findings"]) {
  test(limit + " limits produce incomplete results, never a clean comparison", t => {
    const f = fixture(t), root = path.join(f.root, "site");
    for (const file of ["site/a.txt", "site/b.txt", "site/sub/deep/c.txt"]) f.put(file, "ordinary contents");
    const saved = baseline(f, root);
    const r = f.scan({ webroots: [root], webBaseline: saved, limits: { [limit]: 1 } });
    if (limit === "findings") {
      f.put("site/a.txt", "changed A"); f.put("site/b.txt", "changed B");
      const changed = f.scan({ webroots: [root], webBaseline: saved, limits: { findings: 1 } });
      assert.equal(changed.comparison, "incomplete");
      assert.equal(changed.coverage.complete, false);
    } else {
      assert.equal(r.coverage.complete, false);
      assert.equal(r.comparison, "incomplete");
    }
  });
}
test("time limits and invalid limits fail closed", t => {
  const f = fixture(t);
  const original = Date.now; let calls = 0;
  Date.now = () => ++calls * 20000;
  try { assert.equal(f.scan().coverage.complete, false); } finally { Date.now = original; }
  assert.throws(() => f.scan({ limits: { files: 0 } }));
  assert.throws(() => f.scan({ limits: { unknown: 1 } }));
});
test("port syntax rejects invalid ranges and unresolved values", () => {
  assert.equal(portBinding("8080:80"), "wildcard");
  assert.equal(portBinding("127.0.0.2:8080:80"), "loopback");
  for (const port of ["70000:80", "100-90:80", "${PORT}:80", "host:8080:80"]) assert.throws(() => portBinding(port));
  assert.throws(() => composeServices("services: []"));
});

test("scanner performs no target execution, network operations or writes", t => {
  const f = fixture(t), root = path.join(f.root, "site");
  f.put("site/index.php", "inert PHP source");
  f.put("etc/redis.conf", "protected-mode no\n");
  const Module = require("node:module"), net = require("node:net");
  const originalLoad = Module._load, originalFetch = global.fetch;
  const allowed = new Set(["../src/web-exposure", "node:path", "node:crypto", "node:net", "./web-files", "node:fs"]);
  const modules = ["../src/web-exposure", "../src/web-files"].map(x => require.resolve(x));
  const cached = modules.map(x => require.cache[x]);
  const replaced = [];
  let forbiddenCalls = 0;
  const deny = () => { forbiddenCalls++; throw new Error("forbidden scanner action"); };
  const originalOpen = fs.openSync;
  replaced.push([fs, "openSync", originalOpen]);
  fs.openSync = (file, flags, ...args) => {
    if (typeof flags !== "number" || flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND)) return deny();
    return originalOpen(file, flags, ...args);
  };
  for (const [object, names] of [[fs, ["writeFileSync", "appendFileSync", "writeSync", "mkdirSync", "unlinkSync", "renameSync", "chmodSync", "rmSync"]],
    [net, ["connect", "createConnection", "createServer"]]]) {
    for (const name of names) { replaced.push([object, name, object[name]]); object[name] = deny; }
  }
  Module._load = (request, ...args) => {
    if (!allowed.has(request)) return deny();
    return originalLoad.call(Module, request, ...args);
  };
  global.fetch = deny;
  for (const module of modules) delete require.cache[module];
  try {
    const isolated = require("../src/web-exposure");
    const r = isolated.scanWebExposure({ targetRoot: f.root, webroots: [root] });
    assert.equal(r.manifest.entries.length, 1);
    assert.equal(r.coverage.complete, true);
    assert.equal(forbiddenCalls, 0);
  } finally {
    Module._load = originalLoad; global.fetch = originalFetch;
    modules.forEach((name, i) => { require.cache[name] = cached[i]; });
    for (const [object, name, original] of replaced) object[name] = original;
  }
});
