"use strict";

// Static inventory only: no target execution, configuration loading or network.
const fs = require("node:fs");
const path = require("node:path");
const ADVISORY = require("../data/php-readiness.json");
const LIMITS = Object.freeze({ entries: 50000, files: 2000, bytes: 64 * 1024 * 1024,
  fileBytes: 2 * 1024 * 1024, packageBytes: 32 * 1024 * 1024, depth: 24, milliseconds: 10000, records: 2000 });
const SKIP = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", "vendor", ".venv", "venv"]);
const BINARY = /^(?:php(?:\d+(?:\.\d+)?)?(?:-cgi|-fpm)?|php-(?:cgi|fpm)(?:\d+(?:\.\d+)?)?)$/;
const PACKAGE = /^(?:php(?:\d+(?:\.\d+)?)?(?:-[a-z0-9][a-z0-9+.-]*)?|libapache2-mod-php(?:\d+(?:\.\d+)?)?)$/;
const COMPOSE = /^(?:docker-)?compose(?:\.[a-zA-Z0-9_-]+)?\.ya?ml$/;
const DOCKERFILE = /^(?:Dockerfile(?:\.[a-zA-Z0-9_-]+)?|Containerfile(?:\.[a-zA-Z0-9_-]+)?)$/;
const GUIDANCE = "PHP patch status is unknown. Match the deployed runtime and full vendor package revision to the official PHP release and distribution advisory when available. A CLI version, Composer constraint or image tag alone does not verify the serving runtime. PHP: " + ADVISORY.primarySource + "; OX blog index for research updates (no PHP-specific article verified in this snapshot): " + ADVISORY.researchUpdates;

function within(root, file) {
  const relative = path.relative(root, file);
  return relative === "" || (relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative));
}

function packageRecords(text, format) {
  const records = [];
  for (const block of text.split(/\r?\n\s*\r?\n/)) {
    const fields = new Map();
    for (const line of block.split(/\r?\n/)) {
      const match = line.match(format === "dpkg" ? /^(Package|Status|Version):\s*(.*?)\s*$/ : /^(P|V):(.*?)\s*$/);
      if (match) {
        if (fields.has(match[1])) throw new Error("duplicate package field");
        fields.set(match[1], match[2]);
      }
    }
    const name = fields.get(format === "dpkg" ? "Package" : "P");
    if (!name && block.trim()) throw new Error("invalid package record");
    if (!name || !PACKAGE.test(name)) continue;
    if (format === "dpkg") {
      if (!fields.has("Status")) throw new Error("missing package status");
      if (!/^(?:install|hold) ok installed$/.test(fields.get("Status"))) {
        if (/\b(?:unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/.test(fields.get("Status")))
          throw new Error("PHP package installation is incomplete");
        continue;
      }
    }
    const version = fields.get(format === "dpkg" ? "Version" : "V");
    if (!version || version.length > 128 || !/^[0-9][A-Za-z0-9.+:~_-]*$/.test(version)) throw new Error("invalid package version");
    records.push({ kind: "installed-package", name, version, packageManager: format });
  }
  return records;
}

function imageRecord(image) {
  // Exact official image identity. Do not infer contents of arbitrary custom images.
  const match = image.match(/^(?:(?:docker\.io\/)?library\/|docker\.io\/)?php(?=[:@]|$)(.*)$/);
  if (!match) return null;
  const exact = match[1].match(/^:([0-9]+\.[0-9]+\.[0-9]+)(?:-[A-Za-z0-9_.-]+)?(?:@sha256:[a-fA-F0-9]{64})?$/);
  return { kind: "container-declaration", version: exact ? exact[1] : null };
}

function inspectProjectText(base, text) {
  const records = [];
  if (base === "composer.json" || base === "composer.lock") {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("invalid Composer object");
    // These are constraints / resolver overrides, never installed versions.
    const groups = base === "composer.json" ? [data.require, data["require-dev"], data.config?.platform]
      : [data.platform, data["platform-dev"], data["platform-overrides"]];
    if (groups.some(group => group !== undefined && (!group || typeof group !== "object" || (Array.isArray(group) && group.length > 0))))
      throw new Error("invalid Composer dependency map");
    if (groups.some(group => group && typeof group === "object" && Object.hasOwn(group, "php")))
      records.push({ kind: "composer-declaration", version: null });
  } else if (DOCKERFILE.test(base)) {
    if (/^\s*(?:RUN|COPY|ADD)\b[^\r\n]*<</mi.test(text) || /^\s*#\s*escape\s*=\s*[^\\\s]/mi.test(text))
      throw new Error("unsupported Dockerfile syntax");
    const joined = text.replace(/\\\r?\n/g, " ");
    for (const line of joined.split(/\r?\n/)) {
      const match = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*(?:#.*)?$/i);
      if (match) {
        const record = imageRecord(match[1]);
        if (record) records.push(record);
        else if (match[1].includes("$")) throw new Error("unresolved build image");
      }
    }
  } else if (COMPOSE.test(base)) {
    // A bounded reader for block-style service.image declarations, not a YAML loader.
    // Never interpret strings in block scalars or execute interpolation / includes.
    const stack = [];
    let scalarIndent = null;
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim() || /^\s*#/.test(line)) continue;
      const indent = line.match(/^ */)[0].length;
      if (scalarIndent !== null && indent > scalarIndent) continue;
      scalarIndent = null;
      if (/^\s*\t/.test(line) || /^\s*[{[]/.test(line)) throw new Error("unsupported Compose syntax");
      const match = line.match(/^ *(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_.<>-]+)):\s*(.*?)\s*$/);
      if (!match) continue;
      const key = match[1] || match[2] || match[3];
      const value = match[4];
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      const ancestry = stack.map(item => item.key);
      if (/^[|>]/.test(value)) {
        if (ancestry.length === 2 && ancestry[0] === "services" && key === "image") throw new Error("unsupported image scalar");
        scalarIndent = indent; continue;
      }
      if (key === "<<" || key === "include" || key === "extends" || /^[&*]/.test(value)
          || ((key === "services" || ancestry[0] === "services") && /^[{[]/.test(value)))
        throw new Error("Compose indirection requires review");
      if (ancestry.length === 2 && ancestry[0] === "services" && key === "image") {
        const image = value.match(/^(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s#]+))\s*(?:#.*)?$/);
        if (!image) throw new Error("unresolved Compose image");
        const ref = image[1] || image[2] || image[3];
        const record = imageRecord(ref);
        if (record) records.push(record);
        else if (ref.includes("$")) throw new Error("unresolved Compose image");
      }
      if (!value || value.startsWith("#")) stack.push({ key, indent });
    }
  }
  return records;
}

function scanPhpReadiness(options = {}) {
  const root = path.resolve(options.targetRoot || "/");
  const limits = { ...LIMITS, ...options.limits };
  for (const [key, value] of Object.entries(limits))
    if (!Number.isSafeInteger(value) || value < 1 || value > LIMITS[key]) throw new Error("Invalid PHP inventory limit");
  const exclusions = (options.excludePaths || []).map(item => path.resolve(item));
  const started = Date.now();
  const records = [], problems = [], problemKeys = new Set(), recordKeys = new Set(), visited = new Set();
  const inventory = { dpkg: "not-observed", apk: "not-observed" };
  let entries = 0, files = 0, bytes = 0, stopped = false;
  const display = file => "/" + path.relative(root, file).split(path.sep).join("/");
  function problem(file, reason) {
    const key = display(file) + ":" + reason;
    if (!problemKeys.has(key)) {
      problemKeys.add(key);
      if (problems.length < 40) problems.push({ path: display(file), reason });
    }
  }
  function budget(file) {
    if (stopped) return false;
    if (Date.now() - started >= limits.milliseconds) {
      problem(file, "time-limit"); stopped = true;
    }
    return !stopped;
  }
  function allowed(file) {
    if (!within(root, file)) { problem(root, "outside-root"); return false; }
    if (exclusions.some(excluded => within(excluded, file))) { problem(file, "excluded"); return false; }
    return budget(file);
  }
  function stat(file, parents = true) {
    if (!allowed(file)) return null;
    try {
      if (parents) {
        let current = root;
        const segments = path.relative(root, file).split(path.sep).filter(Boolean);
        for (const segment of segments.slice(0, -1)) {
          current = path.join(current, segment);
          const parent = fs.lstatSync(current);
          if (parent.isSymbolicLink()) { problem(current, "symlink-directory"); return null; }
          if (!parent.isDirectory()) return null;
        }
      }
      return fs.lstatSync(file);
    } catch (error) {
      if (!["ENOENT", "ENOTDIR"].includes(error.code)) problem(file, "unreadable");
      return null;
    }
  }
  function record(file, item) {
    const key = display(file) + JSON.stringify(item);
    if (recordKeys.has(key)) return;
    if (records.length >= limits.records) { problem(file, "record-limit"); stopped = true; return; }
    recordKeys.add(key);
    records.push({ ...item, path: display(file), patchStatus: "unknown" });
  }
  function read(file, maxBytes) {
    const before = stat(file);
    if (!before) return null;
    if (!before.isFile()) { problem(file, "not-regular-file"); return null; }
    if (++files > limits.files) { problem(file, "file-limit"); stopped = true; return null; }
    if (before.size > maxBytes) { problem(file, "file-size-limit"); return null; }
    if (bytes + before.size > limits.bytes) { problem(file, "byte-limit"); stopped = true; return null; }
    let fd;
    try {
      fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
        throw new Error("changed");
      const data = Buffer.alloc(before.size + 1);
      let offset = 0;
      while (offset < data.length) {
        if (!budget(file)) return null;
        const size = fs.readSync(fd, data, offset, Math.min(65536, data.length - offset), offset);
        if (!size) break;
        offset += size;
      }
      bytes += offset;
      const after = fs.fstatSync(fd);
      const linked = stat(file);
      if (offset !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
          || !linked?.isFile() || linked.dev !== before.dev || linked.ino !== before.ino) throw new Error("changed");
      return data.subarray(0, offset).toString("utf8");
    } catch (_error) { problem(file, "unreadable-or-changed"); return null; }
    finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  function walk(directory, recursive, inspect, depth = 0) {
    if (visited.has(directory) || !budget(directory)) return;
    const info = stat(directory);
    if (!info) return;
    if (!info.isDirectory()) { problem(directory, "not-directory"); return; }
    if (depth > limits.depth) { problem(directory, "depth-limit"); return; }
    visited.add(directory);
    let handle;
    try {
      handle = fs.opendirSync(directory);
      let entry;
      while (budget(directory) && (entry = handle.readSync())) {
        if (++entries > limits.entries) { problem(directory, "entry-limit"); stopped = true; break; }
        const file = path.join(directory, entry.name);
        if (!allowed(file)) continue;
        if (entry.isDirectory()) {
          if (recursive && !SKIP.has(entry.name)) walk(file, true, inspect, depth + 1);
        } else {
          if (entry.isSymbolicLink() && recursive) problem(file, "symlink-not-followed");
          inspect(file, entry);
        }
      }
    } catch (_error) { problem(directory, "unlistable-directory"); }
    finally { if (handle) handle.closeSync(); }
  }
  const mapped = absolute => path.join(root, absolute.replace(/^\/+/, ""));
  const rootInfo = stat(root, false);
  if (!rootInfo?.isDirectory()) problem(root, "invalid-root");
  else {
    for (const [format, location] of [["dpkg", "/var/lib/dpkg/status"], ["apk", "/lib/apk/db/installed"]]) {
      // On merged-/usr hosts, use the explicit alternative metadata location
      // instead of traversing /lib's directory link. Other link targets are not followed.
      let file = mapped(location);
      if (format === "apk") {
        const lib = stat(mapped("/lib"));
        if (lib?.isSymbolicLink()) file = mapped("/usr/lib/apk/db/installed");
      }
      const text = read(file, limits.packageBytes);
      if (text !== null) {
        try { for (const item of packageRecords(text, format)) record(file, item); inventory[format] = "read"; }
        catch (_error) { inventory[format] = "incomplete"; problem(file, "malformed-package-metadata"); }
      } else if (problemKeys.size && stat(file)) inventory[format] = "incomplete";
    }
    for (const location of ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"])
      walk(mapped(location), false, (file, entry) => {
        if (BINARY.test(entry.name) && (entry.isFile() || entry.isSymbolicLink()))
          record(file, { kind: entry.isSymbolicLink() ? "binary-link" : "binary-path", version: null });
      });
    for (const location of ["/etc/php.ini", "/etc/php-fpm.conf", "/usr/local/etc/php.ini", "/usr/local/etc/php-fpm.conf"]) {
      const file = mapped(location), info = stat(file);
      if (info?.isFile() || info?.isSymbolicLink()) record(file, { kind: "configuration-path", version: null });
    }
    for (const location of ["/etc/php", "/etc/php-fpm.d", "/usr/local/etc/php", "/usr/local/etc/php-fpm.d"])
      walk(mapped(location), true, (file, entry) => {
        if (/\.(?:ini|conf)$/.test(entry.name) && (entry.isFile() || entry.isSymbolicLink()))
          record(file, { kind: "configuration-path", version: null });
      });
    for (const location of ["/etc/apache2/mods-available", "/etc/apache2/mods-enabled"])
      walk(mapped(location), false, (file, entry) => {
        if (/^php\d*(?:\.\d+)?\.(?:load|conf)$/.test(entry.name)) record(file, { kind: "apache-module-path", version: null });
      });
    const projectRoots = ["/opt", "/srv", "/var/www"].map(mapped);
    if (options.homePath) {
      const home = path.resolve(options.homePath);
      if (within(root, home)) projectRoots.push(home);
      else problem(root, "home-outside-root");
    }
    for (const directory of projectRoots) walk(directory, true, file => {
      const base = path.basename(file);
      if (!["composer.json", "composer.lock"].includes(base) && !DOCKERFILE.test(base) && !COMPOSE.test(base)) return;
      const text = read(file, limits.fileBytes);
      if (text === null) return;
      try { for (const item of inspectProjectText(base, text)) record(file, item); }
      catch (_error) { problem(file, "unsupported-or-malformed-project-metadata"); }
    });
  }
  const titles = {
    "installed-package": "Installed PHP-related package recorded; patch status is unknown.",
    "binary-path": "PHP binary path observed; runtime version was not executed.",
    "binary-link": "PHP binary link observed; target and runtime version are unverified.",
    "configuration-path": "PHP configuration path observed; running service state is unknown.",
    "apache-module-path": "Apache PHP module configuration observed; activation is unverified.",
    "composer-declaration": "Project declares PHP; its deployed runtime is unverified.",
    "container-declaration": "Container build or service declares a PHP image; deployment is unverified.",
  };
  const findings = records.map(item => ({
    severity: "review", id: "php-readiness-" + item.kind,
    title: titles[item.kind],
    evidence: item.path + (item.name ? ": " + item.name + " " + item.version : item.version ? ": declared image tag " + item.version : ""), guidance: GUIDANCE,
  }));
  if (problemKeys.size) findings.push({ severity: "review", id: "php-readiness-incomplete",
    title: "PHP readiness inspection is incomplete.", evidence: problemKeys.size + " inspection gap(s); see phpReadiness.coverage.",
    guidance: "Review excluded, linked, unsupported, unreadable or limited inputs. No PHP absence or patch-safety conclusion is available. " + GUIDANCE });
  return {
    advisory: { ...ADVISORY }, patchStatus: "unknown", presence: records.length ? "observed" : "not-observed",
    packageInventory: inventory, records, findings,
    coverage: { complete: problemKeys.size === 0, scope: "Configured package databases, common runtime/config paths and selected project declarations only",
      entries, files, bytes, problemCount: problemKeys.size, problems, limits: { ...limits },
      limitations: ["No running service, network reachability, exploitation or patch verification", "No RPM database, container daemon, remote host or custom image inspection", "No target execution or symlink traversal; vendor/dependency/build trees excluded from project discovery", "Composer and image declarations may be unused or differ from deployment; absence is not proof PHP is absent"] },
  };
}

module.exports = { scanPhpReadiness, inspectProjectText, packageRecords, LIMITS };
