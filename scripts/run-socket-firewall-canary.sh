#!/usr/bin/env bash
# Linux Socket Firewall canary (parity with run-socket-firewall-canary.ps1).
# Read-only observations + one sfw-wrapped npm install --package-lock-only.
set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_dir="${repo_root}/logs/socket-firewall-canary"
mkdir -p "${log_dir}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_path="${log_dir}/${stamp}.log"

log() {
  printf '%s\n' "$*" | tee -a "${log_path}" >/dev/null
}

run_logged() {
  local label="$1"
  shift
  local code=0
  log ""
  log "## ${label}"
  log "> $*"
  "$@" >>"${log_path}" 2>&1 || code=$?
  return "${code}"
}

sha256_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    log "Missing: ${path}"
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | tee -a "${log_path}" >/dev/null
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | tee -a "${log_path}" >/dev/null
  else
    log "No sha256sum/shasum available"
  fi
}

cd "${repo_root}"

log "Socket Firewall canary run"
log "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Local: $(date +%Y-%m-%dT%H:%M:%S%z)"
log "Repo: ${repo_root}"

run_logged "node version" node --version || true
run_logged "npm version" npm --version || true
run_logged "sfw command" bash -lc 'command -v sfw' || true
run_logged "sfw npm metadata" npm view sfw version time --json || true

global_npm_root="$(npm root -g 2>/dev/null | head -n 1 || true)"
if [[ -n "${global_npm_root}" ]]; then
  sfw_root="${global_npm_root}/sfw"
  log ""
  log "## sfw global package root"
  log "${sfw_root}"
  log ""
  log "## sfw wrapper package hash"
  sha256_file "${sfw_root}/package.json"
  log ""
  log "## sfw wrapper script hash"
  sha256_file "${sfw_root}/dist/sfw.mjs"
  if [[ -d "${sfw_root}/.sfw-cache" ]]; then
    log ""
    log "## sfw global cache before canary"
    find "${sfw_root}/.sfw-cache" -type f 2>/dev/null | sort | while read -r f; do
      sha256_file "${f}"
    done
  fi
else
  log ""
  log "## sfw global package root"
  log "Unable to resolve npm root -g."
fi

exit_code=0
run_logged "socket firewall canary" npm run canary:socket-firewall || exit_code=$?

if [[ -n "${global_npm_root:-}" && -d "${global_npm_root}/sfw/.sfw-cache" ]]; then
  log ""
  log "## sfw global cache after canary"
  find "${global_npm_root}/sfw/.sfw-cache" -type f 2>/dev/null | sort | while read -r f; do
    sha256_file "${f}"
  done
fi

log ""
log "## cache observation"
if [[ -d "${repo_root}/.sfw-cache" ]]; then
  find "${repo_root}/.sfw-cache" -printf '%p %s %TY-%Tm-%TdT%TH:%TM\n' 2>/dev/null | tee -a "${log_path}" >/dev/null \
    || find "${repo_root}/.sfw-cache" -type f 2>/dev/null | tee -a "${log_path}" >/dev/null
else
  log "No .sfw-cache directory observed under repo root."
fi

log ""
log "Exit code: ${exit_code}"
log "Log: ${log_path}"
exit "${exit_code}"
