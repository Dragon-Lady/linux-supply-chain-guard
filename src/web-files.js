"use strict";

// Linux-only, descriptor-anchored inspection. No target code or commands run.
const fs = require("node:fs");
const path = require("node:path");
const DEFAULT_LIMITS = Object.freeze({ entries: 50000, files: 10000, bytes: 128 * 1024 * 1024,
  fileBytes: 8 * 1024 * 1024, configBytes: 1024 * 1024, depth: 32, milliseconds: 10000, findings: 2000 });
function within(root, file) {
  const relative = path.relative(root, file);
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(".." + path.sep));
}

function createReader(options) {
  const root = path.resolve(options.targetRoot || "/");
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  for (const [key, value] of Object.entries(limits)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key) || !Number.isSafeInteger(value) || value < 1 || value > DEFAULT_LIMITS[key])
      throw new Error("Invalid web inspection limit");
  }
  const exclusions = (options.excludePaths || []).map(x => path.resolve(x));
  const problems = [], seenProblems = new Set();
  const counts = { entries: 0, files: 0, bytes: 0 };
  const start = Date.now();
  let stopped = false, rootFD, gapEvents = 0;
  const display = file => within(root, file) ? "/" + path.relative(root, file).split(path.sep).join("/") : "[outside target root]";
  function gap(file, reason) {
    gapEvents++;
    const key = display(file) + ":" + reason;
    if (seenProblems.has(key)) return;
    seenProblems.add(key);
    if (problems.length < 40) problems.push({ path: display(file), reason });
  }
  function budget(file) {
    if (Date.now() - start >= limits.milliseconds) { gap(file, "time-limit"); stopped = true; }
    return !stopped;
  }
  function allowed(file) {
    if (!within(root, file)) { gap(file, "outside-root"); return false; }
    if (exclusions.some(x => within(x, file))) { gap(file, "excluded"); return false; }
    return budget(file);
  }
  const dirFlags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
  function errorGap(file, error, required) {
    if (error.code === "ENOENT") { if (required) gap(file, "missing-or-not-directory"); }
    else gap(file, "unreadable-or-symlink");
  }
  try {
    // Following the explicitly selected root is deliberate; all discovered
    // components below this descriptor are opened with O_NOFOLLOW.
    rootFD = fs.openSync(fs.realpathSync(root), dirFlags);
  } catch (_error) { gap(root, "invalid-root"); }
  function anchored(file, callback, required = false) {
    if (rootFD === undefined || !allowed(file)) return null;
    const parts = path.relative(root, file).split(path.sep).filter(Boolean);
    let parent = rootFD;
    try {
      for (const part of parts.slice(0, -1)) {
        const next = fs.openSync(`/proc/self/fd/${parent}/${part}`, dirFlags);
        if (parent !== rootFD) fs.closeSync(parent);
        parent = next;
      }
      return callback(parts.length ? `/proc/self/fd/${parent}/${parts.at(-1)}` : `/proc/self/fd/${rootFD}`, parts.length === 0);
    } catch (error) { errorGap(file, error, required); return null; }
    finally { if (parent !== rootFD) fs.closeSync(parent); }
  }
  function stat(file, required = false) {
    return anchored(file, (p, isRoot) => isRoot ? fs.fstatSync(rootFD) : fs.lstatSync(p), required);
  }
  function read(file, maxBytes = limits.fileBytes, required = false) {
    return anchored(file, p => {
      const before = fs.lstatSync(p);
      let fd;
      try {
        if (!before.isFile()) { gap(file, "not-regular-file"); return null; }
        if (++counts.files > limits.files) { gap(file, "file-limit"); stopped = true; return null; }
        if (before.size > maxBytes) { gap(file, "file-size-limit"); return null; }
        if (counts.bytes + before.size + 1 > limits.bytes) { gap(file, "byte-limit"); stopped = true; return null; }
        fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size)
          throw new Error("changed");
        const data = Buffer.alloc(before.size + 1);
        let offset = 0;
        while (offset < data.length) {
          if (!budget(file)) return null;
          const size = fs.readSync(fd, data, offset, Math.min(65536, data.length - offset), offset);
          if (!size) break;
          offset += size;
        }
        counts.bytes += offset;
        const after = fs.fstatSync(fd), linked = fs.lstatSync(p);
        if (offset !== before.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
            || before.mode !== after.mode || !linked.isFile() || before.dev !== linked.dev || before.ino !== linked.ino)
          throw new Error("changed");
        return { data: data.subarray(0, offset), stat: after };
      } catch (_error) { gap(file, "unreadable-or-changed"); return null; }
      finally { if (fd !== undefined) fs.closeSync(fd); }
    }, required);
  }
  function walk(directory, inspect, { required = false, skip = new Set(), depth = 0 } = {}) {
    if (depth > limits.depth) { gap(directory, "depth-limit"); return; }
    anchored(directory, (p, isRoot) => {
      // Missing optional paths are handled by anchored(), not as failures.
      const fd = fs.openSync(p, isRoot ? dirFlags & ~fs.constants.O_NOFOLLOW : dirFlags);
      let handle;
      try {
        // opendir follows our own descriptor, never a target-controlled link.
        const before = fs.fstatSync(fd);
        handle = fs.opendirSync(`/proc/self/fd/${fd}`);
        let entry;
        while (budget(directory) && (entry = handle.readSync())) {
          if (++counts.entries > limits.entries) { gap(directory, "entry-limit"); stopped = true; break; }
          const file = path.join(directory, entry.name);
          if (!allowed(file)) continue;
          if (entry.isDirectory()) {
            if (!skip.has(entry.name)) walk(file, inspect, { required: true, skip, depth: depth + 1 });
          } else if (entry.isSymbolicLink()) gap(file, "symlink-not-followed");
          else inspect(file, entry);
        }
        const after = fs.fstatSync(fd);
        if (before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) gap(directory, "directory-changed");
      } catch (_error) { gap(directory, "unlistable-or-changed-directory"); }
      finally { if (handle) handle.closeSync(); if (fd !== undefined) fs.closeSync(fd); }
    }, required);
  }
  return { root, limits, display, gap, stat, read, walk, budget, counts,
    get gapEvents() { return gapEvents; },
    get problemCount() { return seenProblems.size; }, problems,
    mapped: x => path.join(root, x.replace(/^\/+/, "")),
    close() { if (rootFD !== undefined) { fs.closeSync(rootFD); rootFD = undefined; } } };
}
module.exports = { createReader, within, DEFAULT_LIMITS };
