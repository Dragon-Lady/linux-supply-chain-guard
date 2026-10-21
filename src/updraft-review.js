"use strict";

const path = require("node:path");
const { TextDecoder } = require("node:util");
const { createReader, within } = require("./web-files");
const SOURCES = Object.freeze([
  "https://teamupdraft.com/blog/security-incident-october-2026/",
  "https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/",
  "https://nethemba.com/updraftcentral-backdoor-analysis/",
]);
const GUIDANCE = "Preserve evidence and review from a trusted administrative environment. Verify UpdraftCentral keys directly on the site, inspect files and account capabilities, and follow the vendor and researcher advisories. A marker is not proof of execution or attribution; no matches does not establish a clean site.";
const ELEVATED = new Set(["manage_options", "install_plugins", "activate_plugins", "edit_plugins", "edit_users", "promote_users"]);
const WORD = /^[a-zA-Z0-9_-]{1,100}$/;

// Deliberately accept a small, sanitized JSON projection, never a raw database
// dump, PHP serialization, credentials, or executable site configuration.
function validateEvidence(value) {
  const exact = (x, keys) => x && typeof x === "object" && !Array.isArray(x)
    && Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
  const words = x => Array.isArray(x) && x.length <= 200 && x.every(v => typeof v === "string" && WORD.test(v))
    && new Set(x).size === x.length;
  if (!exact(value, ["schema", "keys", "users", "optionNames"]) || value.schema !== 1
      || !exact(value.keys, ["cloud", "selfHosted", "unknown"])
      || !Object.values(value.keys).every(n => Number.isSafeInteger(n) && n >= 0 && n <= 100000)
      || !Array.isArray(value.users) || value.users.length > 10000
      || !Array.isArray(value.optionNames) || value.optionNames.length > 10000
      || !value.optionNames.every(x => typeof x === "string" && /^[a-zA-Z0-9_.-]{1,200}$/.test(x))
      || new Set(value.optionNames).size !== value.optionNames.length) throw new Error("invalid evidence");
  const ids = new Set();
  for (const user of value.users) {
    if (!exact(user, ["id", "roles", "capabilities"]) || !Number.isSafeInteger(user.id) || user.id < 1
        || ids.has(user.id) || !words(user.roles) || !words(user.capabilities)) throw new Error("invalid user");
    ids.add(user.id);
  }
  return value;
}

function scanUpdraftReview(options = {}) {
  const roots = [...new Set((options.wordpressRoots || []).map(x => path.resolve(x)))];
  const logs = [...new Set((options.updraftLogs || []).map(x => path.resolve(x)))];
  const evidenceFile = options.wordpressEvidence ? path.resolve(options.wordpressEvidence) : null;
  const requested = Boolean(roots.length || logs.length || evidenceFile);
  const findings = [], layers = { files: "not-selected", logs: "not-selected", database: "not-selected" };
  const result = { requested, incident: "updraftcentral-key-compromise-october-2026",
    advisory: { checkedOn: "2026-10-20", sources: SOURCES,
      vendorRevocationRelease: ["1.26.13", "2.26.13"],
      note: "Version alone does not verify key revocation or remove an existing backdoor. Researchers report a revocation cutoff gap; inspect remaining keys." },
    compromiseStatus: "unknown", layers, findings,
    coverage: { complete: true, scope: "explicitly selected inputs only; omitted layers are not inspected", problems: [], problemCount: 0 } };
  if (!requested) return result;
  const reader = createReader(options);
  const paths = [...roots, ...logs, ...(evidenceFile ? [evidenceFile] : [])];
  if (paths.some(file => !within(reader.root, file))) {
    reader.close(); throw new Error("WordPress roots, logs and evidence must be inside the target root");
  }
  function add(file, id, severity, title, suffix = "") {
    const evidence = reader.display(file) + suffix;
    if (findings.some(x => x.id === "updraft-" + id && x.evidence === evidence)) return;
    if (findings.length >= reader.limits.findings) { reader.gap(file, "finding-limit"); return; }
    findings.push({ id: "updraft-" + id, severity, title, evidence, guidance: GUIDANCE });
  }
  function readText(file) {
    const data = reader.read(file, reader.limits.fileBytes, true)?.data;
    if (!data) { reader.gap(file, "input-not-inspected"); return null; }
    try {
      if (data.includes(0)) throw new Error("binary input");
      return new TextDecoder("utf-8", { fatal: true }).decode(data);
    } catch (_error) { reader.gap(file, "unsupported-text-encoding"); return null; }
  }
  function inspectPHP(file) {
    const text = readText(file);
    if (text === null) return;
    if (/keeps option storage tidy|Improves cron tasks efficiency|keep service accounts out of the main user list/.test(text))
      add(file, "published-plugin-marker", "warning", "A published backdoor text marker appears in a selected PHP file.");
    const cookie = /\bwp_set_auth_cookie\s*\(/.test(text), query = /\$_GET\b/.test(text);
    const token = /\bhash_equals\s*\(/.test(text);
    if (cookie && ((token && /_sync_token\b/.test(text))
        || (/\bpre_user_query\b/.test(text) && /\bpre_count_users\b/.test(text))
        || (query && /\bhash_equals\s*\(\s*['"][A-Za-z0-9_-]{20,}['"]/.test(text))))
      add(file, "backdoor-code-markers", "warning", "A combination of published backdoor code markers appears in a selected PHP file.");
    else if (cookie && query)
      add(file, "url-login-review", "review", "A selected PHP file references URL input and authentication cookies; verify its purpose.");
    if (/\badd_filter\s*\(\s*['"]all_plugins['"]/.test(text)
        && /\bplugin_basename\s*\(\s*__FILE__\s*\)/.test(text) && /\bunset\s*\(/.test(text))
      add(file, "plugin-hiding-review", "review", "A selected PHP file contains plugin-list hiding markers; inspect the implementation.");
  }
  try {
    if (roots.length) {
      const before = reader.gapEvents;
      for (const root of roots) {
        if (!reader.stat(root, true)?.isDirectory()) { reader.gap(root, "invalid-wordpress-root"); continue; }
        // This is a deployment path supplied by the operator, not PHP discovery.
        // Never load wp-config.php or bootstrap WordPress to locate custom paths.
        const content = path.join(root, "wp-content");
        if (!reader.stat(content, true)?.isDirectory()) { reader.gap(content, "missing-wordpress-content"); continue; }
        for (const name of ["plugins", "mu-plugins", "upgrade"]) {
          const directory = path.join(content, name);
          reader.walk(directory, (file, entry) => {
            if (!entry.isFile()) { reader.gap(file, "not-regular-file"); return; }
            if (/\.(?:php\d*|phtml|inc)$/i.test(file)) inspectPHP(file);
          }, { required: name === "plugins" });
        }
      }
      layers.files = reader.gapEvents === before ? "inspected" : "incomplete";
    }
    if (logs.length) {
      const before = reader.gapEvents;
      for (const file of logs) {
        const text = readText(file);
        if (text === null) continue;
        if (!text.trim()) { reader.gap(file, "empty-log"); continue; }
        // Events can be legitimate or rejected attempts. Never echo lines,
        // query tokens, user agents, IPs, or claim successful exploitation.
        if (/probe\.central\.updraftplus\.com/.test(text))
          add(file, "log-probe-marker", "warning", "A published UpdraftCentral probe marker appears in the selected log.");
        if (/Command received:\s*plugin\.(?:upload_plugin|delete_plugin)\b/.test(text))
          add(file, "log-plugin-command", "review", "An UpdraftCentral plugin upload or deletion command is recorded; correlate with authorized changes.");
        if (/WordPress\/[^\s";]+;\s*class-udrpc\.php(?:["\s]|$)/.test(text))
          add(file, "log-client-marker", "review", "A shortened UpdraftCentral client identifier appears in the selected log.");
        if (/[?&]_[A-Za-z0-9]{4,10}=[A-Za-z0-9_]{32}(?:[&"\s]|$)/.test(text))
          add(file, "log-trigger-shape", "review", "A request matches a published backdoor trigger shape; correlate with files and response evidence.");
      }
      layers.logs = reader.gapEvents === before ? "inspected" : "incomplete";
    }
    if (evidenceFile) {
      const before = reader.gapEvents, text = readText(evidenceFile);
      if (text !== null) {
        try {
          const data = validateEvidence(JSON.parse(text));
          result.keyCounts = data.keys;
          if (data.keys.cloud || data.keys.unknown)
            add(evidenceFile, "connection-keys-review", "warning", "The supplied export reports cloud or unclassified connection keys; verify provenance and revocation on the site.");
          for (const user of data.users) {
            if (!reader.budget(evidenceFile)) break;
            if (!user.roles.includes("administrator") && user.capabilities.some(x => ELEVATED.has(x)))
              add(evidenceFile, "nonadmin-capabilities", "warning", "A non-administrator account has administrative capabilities in the supplied export; verify authorization.", "#user-id=" + user.id);
          }
          if (data.optionNames.some(x => x.endsWith("_sync_token")))
            add(evidenceFile, "token-option-review", "review", "The supplied export contains an option name matching a published suffix; correlate with suspect plugins.");
        } catch (_error) { reader.gap(evidenceFile, "invalid-sanitized-evidence"); }
      }
      layers.database = reader.gapEvents === before ? "inspected" : "incomplete";
    }
  } finally { reader.close(); }
  result.coverage = { ...result.coverage, complete: reader.problemCount === 0,
    problemCount: reader.problemCount, problems: reader.problems, counts: reader.counts };
  if (reader.problemCount) findings.push({ id: "updraft-review-incomplete", severity: "review",
    title: "UpdraftCentral inspection is incomplete.", evidence: `${reader.problemCount} gap(s); see updraftReview.coverage.`,
    guidance: "Resolve skipped, missing, unreadable, malformed or limited inputs. Unselected layers remain uninspected; no clean-site conclusion is available." });
  return result;
}

module.exports = { scanUpdraftReview, validateEvidence };
