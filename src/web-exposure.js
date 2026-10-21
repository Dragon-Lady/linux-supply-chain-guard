"use strict";

const path = require("node:path");
const crypto = require("node:crypto");
const { isIP } = require("node:net");
const { createReader, within } = require("./web-files");
const SKIP = new Set([".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "dist", "build", "coverage", ".next"]);
const COMPOSE = /^(?:docker-)?compose(?:\.[a-zA-Z0-9_-]+)?\.ya?ml$/;
const SOURCE = "https://norforge.com/blog/inside_cairn";
const NETWORK_GUIDANCE = "Verify the active service, authentication, firewall and reverse proxy from a trusted administrative context. Restrict access to intended clients. This is a local declaration, not proof of internet reachability or compromise.";

function stripComment(line, markers = "#") {
  let quote = "", escaped = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (escaped) { escaped = false; continue; }
    if (c === "\\" && quote === '"') { escaped = true; continue; }
    if (quote) { if (c === quote) quote = ""; }
    else if (c === '"' || c === "'") quote = c;
    else if (markers.includes(c)) return line.slice(0, i).trimEnd();
  }
  if (quote) throw new Error("unterminated string");
  return line.trimEnd();
}
function scalar(value) {
  value = value.trim();
  if (/^["']/.test(value)) {
    if (value.at(-1) !== value[0] || /[\\\r\n]/.test(value)) throw new Error("unsupported scalar");
    return value.slice(1, -1);
  }
  return value;
}
function tokens(value) {
  const found = value.match(/"(?:[^"\\]|\\.)*"|'[^']*'|[^\s]+/g) || [];
  return found.map(scalar);
}
function bindClass(value) {
  value = value.replace(/^\[|\]$/g, "").replace(/^-/, "").toLowerCase();
  if (value === "*" || value === "0.0.0.0" || value === "::" || value === "0:0:0:0:0:0:0:0") return "wildcard";
  if (value === "localhost" || value === "::1" || value === "0:0:0:0:0:0:0:1"
      || (isIP(value) === 4 && value.startsWith("127.")) || (isIP(value) === 6 && /^::ffff:127\./.test(value))) return "loopback";
  return isIP(value) ? "non-loopback" : "unknown";
}
function bindings(values) {
  const classes = values.map(bindClass);
  if (classes.includes("wildcard")) return "wildcard";
  if (classes.includes("non-loopback")) return "non-loopback";
  if (!classes.length || classes.includes("unknown")) return "unknown";
  return "loopback";
}
function assignments(text, markers = "#;") {
  const groups = new Map([["global", new Map()]]);
  let group = groups.get("global");
  for (const raw of text.split(/\r?\n/)) {
    const line = stripComment(raw, markers).trim();
    if (!line) continue;
    if (line.startsWith("[")) {
      if (!line.endsWith("]")) throw new Error("invalid section");
      // PHP's ordinary section headings are cosmetic; HOST/PATH sections are not.
      if (/^\[(?:HOST|PATH)\s*=/i.test(line)) {
        if (!groups.has(line)) groups.set(line, new Map());
        group = groups.get(line);
      } else group = groups.get("global");
      continue;
    }
    const match = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
    if (!match) throw new Error("unsupported assignment");
    group.set(match[1].toLowerCase(), scalar(match[2]));
  }
  return [...groups.values()];
}

// Restricted block-style Compose reader. No YAML evaluation, interpolation,
// external includes or docker invocation; unsupported forms are coverage gaps.
function composeServices(text) {
  const services = [], stack = [], keys = new Set();
  let scalarIndent = null;
  for (const raw of text.split(/\r?\n/)) {
    const indent = raw.match(/^ */)[0].length;
    if (scalarIndent !== null && (!raw.trim() || indent > scalarIndent)) continue;
    scalarIndent = null;
    const line = stripComment(raw);
    if (!line.trim() || line.trim() === "---") continue;
    if (/\t/.test(raw.slice(0, raw.search(/\S/))) || /^[\[{]/.test(line.trim())) throw new Error("unsupported YAML");
    while (stack.length && stack.at(-1).indent >= indent) stack.pop();
    const ancestry = stack.map(x => x.key);
    if (ancestry[0] === "services" && ancestry.length === 3 && ancestry[2] === "ports") {
      const item = line.trim().match(/^-\s+(.+)$/);
      if (!item || /^[\[{]|^\w+:\s/.test(item[1])) throw new Error("unsupported port mapping");
      services.at(-1).ports.push(scalar(item[1]));
      continue;
    }
    const match = line.trim().match(/^(?:"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)'|([A-Za-z0-9_.<>-]+)):\s*(.*)$/);
    if (!match) {
      if (!ancestry.length || ancestry.length < 3 && ancestry[0] === "services") throw new Error("unsupported YAML");
      continue;
    }
    const key = match[1] || match[2] || match[3], value = match[4];
    if (["include", "extends", "<<"].includes(key) || /^[&*!]/.test(value)) throw new Error("Compose indirection");
    const identity = [...ancestry, key].join("\0");
    if (keys.has(identity)) throw new Error("duplicate Compose key");
    keys.add(identity);
    if (!ancestry.length && key === "services" && value) throw new Error("unsupported services map");
    if (ancestry[0] === "services" && ancestry.length === 1) {
      if (value) throw new Error("unsupported service map");
      services.push({ image: "", ports: [], network: "" });
    }
    if (ancestry[0] === "services" && ancestry.length === 2) {
      if (key === "image" || key === "network_mode") {
        const item = scalar(value);
        if (!item || /[\s[\]{}]/.test(item.replace(/\$\{[^}]*\}/g, "variable"))) throw new Error("unsupported service scalar");
        if (key === "image") services.at(-1).image = item;
        else services.at(-1).network = item;
      }
      if (key === "ports" && value && value !== "[]") throw new Error("unsupported ports list");
    }
    if (/^[|>]/.test(value)) {
      if (["image", "ports", "network_mode"].includes(key) && ancestry.length === 2) throw new Error("unsupported scalar");
      scalarIndent = indent;
    } else if (!value) stack.push({ key, indent });
  }
  return services;
}
function imageRole(image) {
  const name = image.replace(/^docker\.io\//, "").replace(/^library\//, "").split(/[:@]/)[0];
  if (["adminer", "phpmyadmin", "phpmyadmin/phpmyadmin", "portainer/portainer-ce", "portainer/portainer-ee"].includes(name)) return "management-panel";
  if (["redis", "memcached"].includes(name)) return "cache-store";
  return null;
}
function portBinding(port) {
  if (/[$!&*]|\s/.test(port)) throw new Error("unresolved port");
  const match = port.match(/^(?:(\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}):)?(?:(\d+(?:-\d+)?):)?(\d+(?:-\d+)?)(?:\/(tcp|udp))?$/);
  if (!match) throw new Error("unsupported port");
  for (const range of [match[2], match[3]].filter(Boolean)) {
    const nums = range.split("-").map(Number);
    if (nums.some(x => x < 1 || x > 65535) || nums.length === 2 && nums[0] > nums[1]) throw new Error("invalid port");
  }
  return match[1] ? bindClass(match[1]) : "wildcard";
}

function scanWebExposure(options = {}) {
  const reader = createReader(options), findings = [], records = [], inspected = new Set();
  const webroots = [...new Set((options.webroots || []).map(x => path.resolve(x)))].sort();
  if (options.webBaseline && !webroots.length) { reader.close(); throw new Error("A webroot baseline requires --webroot"); }
  for (const root of webroots) if (!within(reader.root, root)) { reader.close(); throw new Error("Webroots must be inside the selected target root"); }
  if (options.webBaseline && webroots.some(root => within(root, path.resolve(options.webBaseline)))) {
    reader.close(); throw new Error("Keep the web baseline outside selected webroots");
  }
  const manifest = { schema: 1, algorithm: "sha256", complete: true, roots: webroots.map(reader.display), entries: [] };
  let comparison = "not-requested", webrootComplete = true;
  function add(file, id, severity, title, guidance = NETWORK_GUIDANCE) {
    if (findings.length >= reader.limits.findings) { reader.gap(file, "finding-limit"); return; }
    if (findings.some(x => x.id === id && x.evidence === reader.display(file))) return;
    findings.push({ id, severity, title, evidence: reader.display(file), guidance });
  }
  function inspect(file, kind, callback, required = false) {
    if (inspected.has(file)) return;
    inspected.add(file);
    const result = reader.read(file, reader.limits.configBytes, required);
    if (!result) return;
    if (records.length >= reader.limits.findings) { reader.gap(file, "record-limit"); return; }
    records.push({ kind, path: reader.display(file), state: "declaration-only" });
    try {
      if (result.data.includes(0)) throw new Error("binary configuration");
      callback(result.data.toString("utf8"), file);
    } catch (_error) { reader.gap(file, "unsupported-or-malformed-configuration"); }
  }
  function webmin(text, file) {
    const settings = assignments(text)[0];
    const bind = settings.has("bind") ? bindings(settings.get("bind").split(/[\s,]+/)) : "wildcard";
    if (bind === "unknown") reader.gap(file, "unresolved-bind-address");
    if (["wildcard", "non-loopback"].includes(bind)) add(file, "web-panel-nonloopback-bind", "review", "Webmin/Usermin configuration permits a non-loopback listener.");
    if (settings.get("ssl") === "0") add(file, "web-panel-cleartext", "warning", "Webmin/Usermin explicitly disables its own TLS listener.");
  }
  function cockpit(text, file) {
    let section = "", listeners = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = stripComment(raw, "#;").trim();
      if (!line) continue;
      if (line.startsWith("[")) { section = line; continue; }
      if (section !== "[Socket]") continue;
      const match = line.match(/^ListenStream\s*=\s*(.*)$/);
      if (match) { if (!match[1]) listeners = []; else listeners.push(match[1]); }
    }
    for (const value of listeners) {
      if (value.startsWith("/") || value.startsWith("@")) continue;
      const match = value.match(/^(?:(\[[0-9a-fA-F:]+\]|[^:]+):)?(\d+)$/);
      if (!match || +match[2] < 1 || +match[2] > 65535) { reader.gap(file, "unsupported-listener"); continue; }
      const bind = match[1] ? bindClass(match[1]) : "wildcard";
      if (bind === "unknown") reader.gap(file, "unresolved-bind-address");
      else if (bind !== "loopback") add(file, "web-panel-nonloopback-bind", "review", "Cockpit socket file declares a non-loopback listener; later overrides may change it.");
    }
  }
  function redis(text, file) {
    const settings = new Map();
    for (const raw of text.split(/\r?\n/)) {
      const line = stripComment(raw).trim();
      if (!line) continue;
      const values = tokens(line), key = values.shift()?.toLowerCase();
      if (key === "include" || key === "aclfile") reader.gap(file, "external-redis-configuration-not-expanded");
      if (key === "user") {
        if (values[0] === "default" && values.includes("on") && values.includes("nopass"))
          add(file, "web-store-redis-passwordless-declaration", "warning", "Redis contains an enabled passwordless default-user declaration; verify the effective ACL.");
      } else settings.set(key, values);
    }
    const bind = settings.has("bind") ? bindings(settings.get("bind")) : "unknown";
    if (settings.has("bind") && bind === "unknown") reader.gap(file, "unresolved-bind-address");
    if (["wildcard", "non-loopback"].includes(bind)) add(file, "web-store-nonloopback-bind", "review", "Redis configuration declares a non-loopback bind; authorization and runtime exposure are unverified.");
    if (settings.get("protected-mode")?.[0] === "no") add(file, "web-store-redis-protection-disabled", "warning", "Redis configuration explicitly disables protected mode.");
    if (settings.has("requirepass") && settings.get("requirepass").length === 1 && settings.get("requirepass")[0] === "")
      add(file, "web-store-redis-empty-password", "warning", "Redis explicitly sets an empty legacy password; verify the effective ACL.");
  }
  function memcached(text, file) {
    const settings = new Map();
    for (const raw of text.split(/\r?\n/)) {
      const line = stripComment(raw).trim();
      if (!line) continue;
      // Debian-style one-option-per-line configuration, not a shell/env file.
      const values = tokens(line);
      if (!/^-[A-Za-z]$/.test(values[0]) || values.length > 2) throw new Error("unsupported memcached option");
      settings.set(values[0], values[1] ?? "");
    }
    for (const key of ["-p", "-U"]) if (settings.has(key)
        && (!/^\d+$/.test(settings.get(key)) || +settings.get(key) > 65535)) throw new Error("invalid port option");
    if (settings.has("-s") && settings.get("-s")) return;
    const bind = settings.has("-l") ? bindings(settings.get("-l").split(",")) : "unknown";
    if (settings.has("-l") && bind === "unknown") reader.gap(file, "unresolved-bind-address");
    if (["wildcard", "non-loopback"].includes(bind)) add(file, "web-store-nonloopback-bind", "warning", "Memcached configuration declares a non-loopback listener; restrict access to trusted clients.");
    if (settings.has("-U") && /^\d+$/.test(settings.get("-U")) && +settings.get("-U") > 0)
      add(file, "web-store-memcached-udp", "warning", "Memcached configuration explicitly enables UDP.");
    if (!settings.has("-l")) add(file, "web-store-bind-unresolved", "review", "Memcached config has no explicit interface restriction; inspect the effective startup arguments.");
  }
  function php(text, file) {
    for (const settings of assignments(text)) {
      const handler = settings.get("session.save_handler")?.toLowerCase();
      if (["redis", "rediscluster", "memcache", "memcached"].includes(handler))
        add(file, "web-session-network-store", "review", "PHP declares a network session handler; verify its actual store, credentials and isolation.");
      const value = settings.get("session.save_path");
      if (value && (!handler || handler === "files")) {
        // N;MODE;path is the documented files-handler syntax. Never echo it.
        const location = value.split(";").at(-1);
        if (!path.posix.isAbsolute(location) || /[$\x00-\x1f]/.test(location)) reader.gap(file, "unresolved-session-directory");
        else {
          const directory = reader.mapped(location), info = reader.stat(directory, true);
          if (info && !info.isDirectory()) reader.gap(directory, "session-path-not-directory");
          else if (info) {
            if (info.mode & 0o004) add(file, "web-session-directory-readable", "warning", "PHP session directory permits other users to list its entries.", "Use a private session directory with appropriate service ownership. Do not read or publish session files; confirm effective PHP overrides and permissions.");
            if (info.mode & 0o002 && !(info.mode & 0o1000)) add(file, "web-session-directory-writable", "warning", "PHP session directory is writable by other users without a sticky bit.", "Restrict session storage to the serving account. Review ACLs and the effective session handler; this check does not read sessions.");
          }
        }
      }
    }
  }
  function compose(text, file) {
    for (const service of composeServices(text)) {
      if (service.image.includes("$") || service.network.includes("$")) { reader.gap(file, "unresolved-compose-value"); continue; }
      const role = imageRole(service.image);
      if (!role) continue;
      if (service.network === "host") add(file, "web-compose-host-network", "review", "A recognized management panel or cache image declares host networking.");
      for (const port of service.ports) {
        const bind = portBinding(port);
        if (bind === "unknown") reader.gap(file, "unresolved-published-address");
        else if (bind !== "loopback") add(file, role === "management-panel" ? "web-panel-published-port" : "web-store-published-port",
          role === "management-panel" ? "review" : "warning", "A recognized " + role + " image declares a published port not restricted to loopback.");
      }
    }
  }
  try {
    for (const location of ["/etc/webmin/miniserv.conf", "/etc/usermin/miniserv.conf"])
      inspect(reader.mapped(location), "management-panel", webmin);
    inspect(reader.mapped("/etc/systemd/system/cockpit.socket"), "management-panel", cockpit);
    reader.walk(reader.mapped("/etc/systemd/system/cockpit.socket.d"), file => {
      if (file.endsWith(".conf")) inspect(file, "management-panel", cockpit, true);
    });
    for (const location of ["/etc/redis/redis.conf", "/etc/redis.conf"]) inspect(reader.mapped(location), "cache-store", redis);
    inspect(reader.mapped("/etc/memcached.conf"), "cache-store", memcached);
    for (const location of ["/etc/php.ini", "/usr/local/etc/php.ini"]) inspect(reader.mapped(location), "php-session", php);
    for (const location of ["/etc/php", "/usr/local/etc/php"])
      reader.walk(reader.mapped(location), file => { if (file.endsWith(".ini")) inspect(file, "php-session", php, true); });
    for (const location of ["/opt", "/srv", "/var/www"])
      reader.walk(reader.mapped(location), file => { if (COMPOSE.test(path.basename(file))) inspect(file, "compose", compose, true); }, { skip: SKIP });
    for (const file of options.webCompose || []) inspect(path.resolve(file), "compose", compose, true);

    for (const root of webroots) {
      const problemsBefore = reader.gapEvents;
      if (!reader.stat(root, true)?.isDirectory()) { reader.gap(root, "invalid-webroot"); webrootComplete = false; continue; }
      reader.walk(root, (file, entry) => {
        if (!entry.isFile()) { reader.gap(file, "not-regular-file"); return; }
        if (/[\x00-\x1f\x7f]/.test(path.relative(root, file))) { reader.gap(root, "unsupported-filename"); return; }
        const content = reader.read(file, reader.limits.fileBytes, true);
        if (!content) return;
        manifest.entries.push({ root: reader.display(root), path: path.relative(root, file).split(path.sep).join("/"),
          sha256: crypto.createHash("sha256").update(content.data).digest("hex"),
          size: content.stat.size, mode: content.stat.mode & 0o7777 });
      }, { required: true });
      if (reader.gapEvents > problemsBefore || !reader.budget(root)) webrootComplete = false;
    }
    manifest.entries.sort((a, b) => a.root.localeCompare(b.root) || a.path.localeCompare(b.path));
    manifest.complete = webrootComplete;
    if (options.webBaseline) {
      comparison = "incomplete";
      const baselineFile = path.resolve(options.webBaseline);
      const baselineReader = createReader({ targetRoot: path.dirname(baselineFile), limits: { fileBytes: reader.limits.fileBytes } });
      let data;
      try { data = baselineReader.read(baselineFile, reader.limits.fileBytes, true)?.data; }
      finally { baselineReader.close(); }
      try {
        if (!data) throw new Error("unreadable baseline");
        const parsed = JSON.parse(data.toString("utf8"));
        const baseline = validateManifest(parsed?.webExposure?.manifest || parsed, manifest.roots, reader.limits.files);
        if (manifest.complete) {
          const comparisonGaps = reader.gapEvents;
          comparison = "matched";
          const previous = new Map(baseline.entries.map(x => [x.root + "\0" + x.path, x]));
          for (const entry of manifest.entries) {
            const key = entry.root + "\0" + entry.path, old = previous.get(key);
            let kind;
            if (!old) kind = "added";
            else if (old.sha256 !== entry.sha256 || old.size !== entry.size) kind = "content-changed";
            else if (old.mode !== entry.mode) kind = "permissions-changed";
            if (kind) { changed(entry, kind); comparison = "changed"; }
            previous.delete(key);
          }
          for (const entry of previous.values()) { changed(entry, "removed"); comparison = "changed"; }
          if (reader.gapEvents > comparisonGaps) comparison = "incomplete";
        }
      } catch (_error) { reader.gap(baselineFile, "invalid-or-unreadable-baseline"); }
    } else if (webroots.length) add(webroots[0], "webroot-baseline-needed", "review", "Webroot hashes recorded without a trusted baseline; unexpected changes cannot yet be determined.",
      "Review this deployment against a trusted source before retaining its manifest. Keep baselines private and outside the webroot. A snapshot of an already compromised deployment is not a trusted baseline.");
  } finally { reader.close(); }
  function changed(entry, kind) {
    const file = reader.mapped(entry.root + "/" + entry.path);
    add(file, "webroot-" + kind, "review", "Webroot file " + kind.replaceAll("-", " ") + " relative to the selected baseline.",
      "Confirm an authorized deployment explains this change. Review application code, upload areas and server configuration; preserve evidence if unexplained. A difference is not proof of a webshell, and unchanged files do not prove the site is uncompromised.");
  }
  if (reader.problemCount) findings.push({ id: "web-exposure-incomplete", severity: "review", title: "Web configuration or webroot inspection is incomplete.",
    evidence: `${reader.problemCount} inspection gap(s); see webExposure.coverage.`,
    guidance: "Resolve unreadable, linked, unsupported, excluded or limited inputs. No clean exposure or webroot-change conclusion is available." });
  return { source: SOURCE, runtimeExposure: "unknown", records, findings, manifest, comparison,
    coverage: { complete: reader.problemCount === 0, ...reader.counts, problemCount: reader.problemCount, problems: reader.problems, limits: reader.limits,
      scope: "Selected local Webmin/Usermin, Cockpit overrides, Redis/Memcached, PHP INI and recognized Compose declarations; explicitly selected webroots",
      limitations: ["No network requests, target execution or live service/authentication/firewall verification; session config checks read directory metadata only",
        "Includes, runtime overrides, custom images and other config formats require separate review; declarations may be inactive",
        "No Cairn attribution, exploit detection or PHP patch verdict; normal changes also differ from a baseline",
        "No discovered symlink traversal; stable snapshots are recommended; reads are not an atomic filesystem snapshot"] } };
}

function validateManifest(data, roots, maxFiles) {
  if (!data || data.schema !== 1 || data.algorithm !== "sha256" || data.complete !== true
      || !Array.isArray(data.roots) || JSON.stringify(data.roots) !== JSON.stringify(roots)
      || !Array.isArray(data.entries) || data.entries.length > maxFiles) throw new Error("invalid manifest");
  const seen = new Set();
  for (const entry of data.entries) {
    if (!entry || !roots.includes(entry.root) || typeof entry.path !== "string" || !entry.path || entry.path.length > 4096
        || entry.path.startsWith("/") || entry.path.split("/").some(x => !x || x === "." || x === "..") || /[\x00-\x1f\x7f]/.test(entry.path)
        || typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.size) || entry.size < 0
        || !Number.isInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777) throw new Error("invalid entry");
    const key = entry.root + "\0" + entry.path;
    if (seen.has(key)) throw new Error("duplicate entry");
    seen.add(key);
  }
  return data;
}

module.exports = { scanWebExposure, composeServices, bindClass, portBinding, validateManifest };
