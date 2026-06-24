"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PATCHED_KERNELS = {
  "8": "4.18.0-553.124.2.el8_10",
  "9": "5.14.0-611.54.4.el9_7",
  "10": "6.12.0-124.56.2.el10_1",
};

const KNOWN_HASHES = new Set([
  "5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b",
]);

const OPENCLAW_FIXED = "2026.4.23";
const OPENCLAW_CONFIG_FILES = new Set([".crabbox.yaml", ".crabbox.yml"]);
const NPM_V12_PREPARE_MIN = "11.16.0";
const ROUNDCUBE_15_FIXED = "1.5.10";
const ROUNDCUBE_16_FIXED = "1.6.11";
const ROUNDCUBE_VULNERABLE_MIN = "1.1.0";
const JOOMLA_JCE_FIXED = "2.9.99.6";
const ITSCAPE_UPSTREAM_FIXED_KERNEL = "6.15.0";
const SPLUNK_20253_REVIEW_MIN = "10.0.0";
const REDCAP_REVIEW_LATEST = "17.1.3";

const KNOWN_DPRK_NPM_PACKAGES = [
  "terminal-logger-utils",
  "pretty-logger-utils",
  "ts-logger-pack",
  "pinno-loggers",
];

const KNOWN_COMPROMISED_NPM_PACKAGES = [
  "atomic-lockfile",
  "csc154-internall-depend",
  "ecto-flag-read",
  "@validate-sdk/v2",
  "google-cloud-secret-manager-config-poc",
];

const ATOMIC_ARCH_AUR_PACKAGE = "atomic-lockfile";

const OTTERCOOKIE_NPM_PACKAGES = [
  "bjs-lint-builders", // push-guard: ignore
  "bjs-lint-builder", // push-guard: ignore
  "bjs-biginteger", // push-guard: ignore
  "hjs-lint-builders", // push-guard: ignore
  "sjs-builders", // push-guard: ignore
  "sjs-builder", // push-guard: ignore
  "npm-doc-builder", // push-guard: ignore
];

const OTTERCOOKIE_TEXT_INDICATORS = [
  "cloudflareinsights.vercel.app", // push-guard: ignore
  "cloudflarefirewall.vercel.app", // push-guard: ignore
  "cloudflaresecurity.vercel.app", // push-guard: ignore
  "cloudflareinsights[.]vercel[.]app", // push-guard: ignore
  "cloudflarefirewall[.]vercel[.]app", // push-guard: ignore
  "cloudflaresecurity[.]vercel[.]app", // push-guard: ignore
  "node test.js",
  "postinstall",
];

const EASY_DAY_JS_TEXT_INDICATORS = [
  "easy-day-js",
  "setup.cjs",
  "node setup.cjs --no-warnings",
  "node setup.cjs –no-warnings",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "23.254.164.92",
  "23.254[.]164.92",
  "23.254.164.92:8000",
  "23.254[.]164.92:8000",
  "23.254.164.123",
  "23.254[.]164.123",
  "23.254.164.123:443",
  "23.254[.]164.123:443",
  "https://23.254.164.92:8000/update/49890878",
  "https://23.254.164[.]92:8000/update/49890878",
  "https://23.254.164.123:443/49890878",
  "https://23.254.164[.]123:443/49890878",
  "hwsrv-1327786.hostwindsdns.com",
  "hwsrv-1327786.hostwindsdns[.]com",
  "hwsrv-1327785.hostwindsdns.com",
  "hwsrv-1327785.hostwindsdns[.]com",
  "/update/49890878",
  "/49890878",
  "protocal.cjs",
  "NodePackages",
  "NvmProtocal",
  "com.nvm.protocal",
  "nvmconf.service",
  ".pkg_history",
  ".pkg_logs",
  "browser-hist-",
  "reqmod",
  "PrimaryUrl",
  "SecondaryUrl",
  "sub_net_resolve",
  "sub_net_splithostport",
  "b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4",
  "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf",
  "ehindero",
  "sergey2016",
];

const PROCWIRE_TEXT_INDICATORS = [
  "procwire",
  "routecraft",
  "endpointmap",
  "bytecraft",
  "staticlayer",
  "node lib/setup.js",
  "endpointmap/lib/registry",
  "bytecraft.xor",
  "files.catbox.moe/j4loim.chk",
  "files[.]catbox[.]moe/j4loim[.]chk",
  "Microsoft-Delivery-Optimization/10.0",
  "Zone.Identifier",
  "[ZoneTransfer]",
  "ZoneId=0",
  "msedge_update",
  "chrome_installer",
  "dotnet_host",
  "onedrive_setup",
  "teams_update",
  "bitsadmin",
  "curl.exe",
  "--ssl-no-revoke",
  "windowsHide: true",
  "deltajohnsons.com",
  "akuznetsov-oss",
  "vpetrov-oss",
];

const WSHU_NET_NPM_PACKAGES = [
  "@apexcraft/nano-key",
  "@briskforge/envcheck",
  "@bytemend/mfebus",
  "@chunklab/hexparse",
  "@frostnode/waitfor",
  "@glitchpad/throttler",
  "@lazyutil/dater",
  "@petitcode/eb-retry",
  "@thymelab/logfx",
  "@tinyfox/shapecheck",
  "@zynkit/jwtbytes",
];

const WSHU_NET_TEXT_INDICATORS = [
  "wshu.net",
  "wshu[.]net",
  "angelmaybeth21-oss",
  "github.com/angelmaybeth21-oss/test",
  "github[.]com/angelmaybeth21-oss/test",
  "smilingdusty233",
  "api.telegram.org",
  "api[.]telegram[.]org",
  "149.154.166.110",
  "149[.]154[.]166[.]110",
  "/tmp/_installer-0/",
  "~/.local/bin/colord",
  "~/.local/bin/haveged",
  "~/.config/systemd/user/colord.service",
  "~/.config/systemd/user/haveged.service",
  "install.nonce",
  "machine.id",
  "2457b2e775a5fe7a9e022ba77074a1b9aacb41b4fc0cc1d8a3dc66546599c5de",
  "b1c7b17f31a84e2596250121c3610ae5e0d592651940dd6c0dd74506f0f38313",
  "11fe3a47333f63fd0e0a32ea16351eb302659aba983c07e4ea3dc9b09b618509",
];

const STITCH_SDK_TEXT_INDICATORS = [
  "@withgoogle/stitch-sdk",
  "stitch-production.org",
  "stitch-production[.]org",
  "172.67.189.185",
  "172[.]67[.]189[.]185",
  "104.21.65.94",
  "104[.]21[.]65[.]94",
  "/api/v1?src=",
  "claude_api_user",
  "gh_api_user",
  "file:~/.npmrc",
  "ba5b2a9a7fe596734fb69bdf1a35071d1a2f435a36e8c870bd4390c562d9f614",
  "638b523ddd3382b622c412e37f274db1a9a6505893fa7236183f0b67a5355e94",
];

const MYRA_NPM_PACKAGES = [
  "apintergrationpost",
];

const MYRA_TEXT_INDICATORS = [
  "192.168.54.1:4444",
  "myra-lab-shared-key",
  "kimijohn01",
  "/usr/local/lib/.libcache.so",
  "/usr/local/lib/.cache-update.sh",
  "/etc/profile.d/.sh.local",
  "systemd-userdbd --user",
  "memfd_exec",
  "memfd_loader",
  "proc_hide",
  "injector",
  "agent_launcher",
  "libcache.so",
  "scripts/install-guard.js",
  "scripts/postinstall-run.js",
];

const MYRA_HOST_ARTIFACTS = [
  "/usr/local/lib/.libcache.so",
  "/usr/local/lib/.cache-update.sh",
  "/etc/profile.d/.sh.local",
];

const POSTCSS_WINDOWS_RAT_NPM_PACKAGES = [
  "postcss-minify-selector-parser",
  "postcss-minify-selector",
  "aes-decode-runner-pro",
];

const POSTCSS_WINDOWS_RAT_TEXT_INDICATORS = [
  "nvidiadriver.net",
  "nvidiadriver[.]net",
  "nvidiadriver.net/verv1432/winpatch-xd7d.win",
  "95.216.92.207:8080",
  "95.216.92[.]207:8080",
  "winPatch.zip",
  "win-driver-xd7d",
  "csshost",
  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\csshost",
];

const SPLUNK_20253_TEXT_INDICATORS = [
  "CVE-2026-20253",
  "PostgreSQL Sidecar Service",
  "PostgreSQL sidecar",
  "/v1/postgres/recovery/backup",
  "/v1/postgres/recovery/restore",
  "pg_restore",
  "pg_dump",
  ".pgpass",
  "backupFile",
  "database parameter",
  "CWE-306",
  "BOD 26-04",
];

const CRYPTO_CLIPPER_TEXT_INDICATORS = [
  "Crypto Clipper",
  "CryptoBandits.A",
  "Trojan:Win32/CryptoBandits.A",
  "localhost:9050",
  "SOCKS5 proxy",
  "portable Tor client",
  "clipboard inspection",
  "clipboard contents",
  "seed phrase",
  "wallet addresses",
  "crypto-address replacement",
  "Possible data exfiltrations using Curl",
  "Suspicious JavaScript processes",
];

const REDCAP_TEXT_INDICATORS = [
  "REDCap",
  "UNC6508",
  "InfiniteRed",
  "Clinical Data Interoperability Services",
  "Project REDCap",
  "redcap_v",
  "redcap/index.php",
  "redcap_version",
];

const FORTINET_CREDENTIAL_EXPOSURE_TEXT_INDICATORS = [
  "FortiBleed",
  "Fortinet credential exposure",
  "FortiGate credential exposure",
  "Fortinet/FortiGate firewall URLs",
  "Fortinet/FortiGate VPN credentials",
  "FortiGate SSL VPN",
  "Fortinet SSL VPN",
  "FortiOS",
  "FortiCloud SSO",
  "FortiCloud login",
  "admin-forticloud-sso-login",
  "config system global",
  "FortiGate configuration export",
  "firewall configuration data",
  "VPN authentication hashes",
  "1.1 billion credential attempts",
  "320,000 FortiGate",
  "73,932",
];

const SOLANA_FAKEFIX_NPM_PACKAGES = [
  "@solana-labs/ancor",
  "@solana-labs/etherjs",
  "@solana-labs/spl-toke",
  "@solana-labs/web3-js",
  "@solana-labs/web3.js",
  "@solana-labs/web3js",
  "cms-github",
  "cms-helpgit",
  "cms-storehub",
  "shopifyto-cms",
  "solana-js-client",
  "solana-mev-bot",
  "solana-rpc-client",
  "solana-web3-community",
  "solana-web3-fixed",
  "solana-web3-fork",
  "solana-web3-lts",
  "solana-web3-patched",
  "solana-web3-stable",
  "solana-web3-v1",
  "to-cms",
];

const SOLANA_FAKEFIX_PYPI_PACKAGES = [
  "solana-cli-py",
  "solana-web3",
  "solana-web3-py",
  "spl-token-py",
];

const SOLANA_FAKEFIX_TEXT_INDICATORS = [
  ".config/solana/id.json",
  ".solana/id.json",
  "wallet.json",
  "keypair.json",
  "api.telegram.org/bot",
  "104.239.66.223:8899",
  "77.90.185.225",
  "raw.githubusercontent.com/PassWord1337/updates/main/install.js",
  "Deno.Command",
  "deno run -A",
  "conhost.exe --headless",
  "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "127.0.0.1:10092",
  "ChromeSetup.exe",
  "aCpsuydgwbasd.exe",
];

const GLASSWASM_OPENVSX_PACKAGES = [
  "exargd/vsblack@0.0.1",
  "vscode/exargd/vsblack@0.0.1",
  "exargd.vsblack-0.0.1.vsix",
  "noellee-doc/flint-debug@0.1.1",
  "vscode/noellee-doc/flint-debug@0.1.1",
  "noellee-doc.flint-debug-0.1.1.vsix",
];

const GLASSWASM_TEXT_INDICATORS = [
  "snqpkebiwrxmoivl.wasm",
  "orybbbdsuqmaapel.wasm",
  "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f",
  "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
  "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
  "dodod.lat",
  "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",
  "getSignaturesForAddress",
  "getTransaction",
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM",
];

const JETBRAINS_AI_KEY_PLUGIN_IDS = [
  "org.sm.yms.toolkit",
  "com.json.simple.kit",
  "org.bug.find.tools",
  "org.translate.ai.simple",
  "com.yy.test.ai.simple",
  "com.dev.ai.toolkit",
  "com.json.view.simple",
  "com.my.git.ai.kit",
  "org.check.ai.ds",
  "com.review.tool.code",
  "org.code.assist.dev.tool",
  "com.coder.ai.dpt",
  "com.my.code.tools",
  "ord.cp.code.ai.kit",
  "com.dp.git.ai.tool",
];

const JETBRAINS_AI_KEY_ENDPOINT_INDICATORS = [
  "39.107.60.51",
  "39.107.60[.]51",
  "39.107.60.51/api/software/key",
  "39.107.60[.]51/api/software/key",
  "/api/software/key",
];

const GLASSWASM_KNOWN_FILE_NAMES = [
  "snqpkebiwrxmoivl.wasm",
  "orybbbdsuqmaapel.wasm",
  "exargd.vsblack-0.0.1.vsix",
  "noellee-doc.flint-debug-0.1.1.vsix",
];

const HADES_PYPI_PACKAGES = {
  bramin: ["0.0.2", "0.0.3", "0.0.4"],
  cmd2func: ["0.2.2", "0.2.3"],
  coolbox: ["0.4.1", "0.4.2"],
  dreamgen: ["1.8.1"],
  "dynamo-release": ["1.5.4"],
  embiggen: ["0.11.97"],
  ensmallen: ["0.8.101"],
  "executor-engine": ["0.3.4", "0.3.5"],
  "executor-http": ["0.1.3", "0.1.4"],
  funcdesc: ["0.2.2", "0.2.3"],
  gpsea: ["0.9.14"],
  "instructor-mcp": ["1.15.2", "1.15.3"],
  "langchain-core-mcp": ["1.4.2", "1.4.3"],
  magique: ["0.6.8", "0.6.9"],
  "magique-ai": ["0.4.4", "0.4.5"],
  mem8: ["6.0.1"],
  "mflux-streamlit": ["0.0.3", "0.0.4"],
  mrbios: ["0.1.1", "0.1.2"],
  "napari-ufish": ["0.0.2", "0.0.3"],
  nucbox: ["0.1.2", "0.1.3"],
  okite: ["0.0.7", "0.0.8"],
  "openai-mcp": ["2.41.1", "2.41.2"],
  "orchestr8-platform": ["3.3.2"],
  "pantheon-agents": ["0.6.1", "0.6.2"],
  "pantheon-toolsets": ["0.5.5", "0.5.6"],
  "phenopacket-store-toolkit": ["0.1.7"],
  ppkt2synergy: ["0.1.1"],
  pyphetools: ["0.9.120"],
  "ray-mcp-server": ["0.2.1"],
  rlask: ["3.1.7"],
  rsquests: ["2.34.3"],
  "spateo-release": ["1.1.2"],
  synago: ["0.1.1", "0.1.2"],
  "tiktoken-mcp": ["0.13.1", "0.13.2"],
  tlask: ["3.1.4"],
  ufish: ["0.1.2", "0.1.3"],
  uprobe: ["0.1.3", "0.1.4"],
};

const HADES_TEXT_INDICATORS = [
  joinParts("Hades - The End for the ", "Damned"),
  joinParts("IfYouYankThisToken", "ItWillNukeTheComputerOfTheOwnerFully"),
  joinParts("results/results-", "*.json"),
  joinParts("format", "-results"),
  joinParts("Run ", "Copilot"),
  joinParts(".bun", "_ran"),
  joinParts("bun-v1.3.", "13"),
  joinParts("bun-v1.3.", "14"),
  joinParts("oven-sh/bun/releases/", "download"),
  "urllib.request",
  "urlretrieve",
  "tempfile.gettempdir",
  "subprocess.run",
  "langchain_core-setup.pth",
  joinParts("thebeautiful", "marchoftime"),
  joinParts("thebeautiful", "snadsoftime"),
  joinParts("/tmp/.sshu", "-setup.js"),
  "/var/run/docker.sock",
  "harden-runner",
];

const HADES_NATIVE_EXTENSION_FILES = new Set([
  "ensmallen_haswell.abi3.so",
  "ensmallen_core2.abi3.so",
]);

const DPRK_NPM_TEXT_INDICATORS = [
  "utils.cjs",
  "/api/validate/keyboard-events",
  "pwdKeyString",
  "Telegram Desktop",
];

const DPRK_SOCKET_IO_LOADER_TERMS = [
  "socket.io",
  "/api/service",
  "0001.dat",
];

const ROUNDCUBE_ROOT_HINTS = [
  "roundcube",
  "roundcubemail",
  "psa-roundcube",
  "3rdparty/roundcube",
  "/webmail/",
];

const ROUNDCUBE_CANDIDATE_FILE_NAMES = new Set([
  "composer.json",
  "composer.lock",
  "index.php",
  "iniset.php",
  "package.xml",
  "CHANGELOG.md",
  "README.md",
]);

const JOOMLA_JCE_ROOT_HINTS = [
  "joomla",
  "administrator/components/com_jce",
  "components/com_jce",
  "plugins/editors/jce",
  "media/com_jce",
  "/jce/",
];

const JOOMLA_JCE_CANDIDATE_FILE_NAMES = new Set([
  "jce.xml",
  "manifest.xml",
  "composer.json",
  "configuration.php",
  "README.md",
  "CHANGELOG.md",
  "error.php",
  "access.log",
  "access_log",
  "error.log",
  "error_log",
]);

const DYNATRACE_TOKEN_PATTERN = /dt0[cs][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64,}/gi;

const DYNATRACE_TEAMPCP_REPO_TERMS = [
  "hard-copilot",
  "hard-csc",
  "hard-iam",
  "local-cluster-setup",
  "nonprod-dtappghrunner",
  "prod-copilot",
  "prod-csc",
  "prod-dtappghrunner",
  "prod-iam",
];

const DYNATRACE_TEAMPCP_SERVICE_TERMS = [
  "dynatrace.scorecards",
  "dynatrace.security.enrichment",
  "dynatrace.security.operations",
  "dynatrace.security.threats.exploits",
  "dynatrace.sensitive.data.center",
  "dynatrace.services",
  "dynatrace.snowflake.connector",
  "dynatrace.software.lifecycle",
  "dynatrace.specktrack",
  "dynatrace.storage.management",
];

const PCPJACK_TEXT_INDICATORS = [
  "PCPJack",
  "chisel_verifier.py",
  "chisel_verified.json",
  "smtp_proxies.csv",
  "smtp.gmail.com:587",
  "38.242.204.245",
  "38.242.204[.]245",
  "213.136.80.73",
  "213.136.80[.]73",
  "/root/.sliver-client/configs/root_localhost.cfg",
  "/root/excalibur/smtp_proxies.csv",
  "StrictHostKeyChecking=no",
  "R:0.0.0.0:",
  "R:.*:",
  "socks5",
];

const PCPJACK_FILE_NAMES = new Set([
  "chisel_verifier.py",
  "chisel_verified.json",
  "smtp_proxies.csv",
  "root_localhost.cfg",
  "sliver-client.cfg",
]);

const PEOPLESOFT_MESH_AGENT_FILES = new Set([
  "meshagent32-azure-ops.exe",
  "meshagent64-azure-ops.exe",
  "meshagent64-v2.exe",
]);

const PEOPLESOFT_EXTORTION_MARKER = "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT";

const PEOPLESOFT_CAMPAIGN_NETWORK_INDICATORS = [
  "azurenetfiles.net",
  "wss://azurenetfiles.net:443/agent.ashx",
  "142.11.200.186",
  "142.11.200.187",
  "142.11.200.188",
  "142.11.200.189",
  "142.11.200.190",
  "176.120.22.24",
];

const GENTLEMEN_KNOWN_HASHES = new Map([
  ["22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67", "Gentlemen ransomware encryptor"],
  ["078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b", "PsExec binary embedded/dropped by Gentlemen ransomware"],
  ["fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68", "Gentlemen ransomware wallpaper bitmap"],
]);

const GENTLEMEN_TOOLKIT_FILES = new Set([
  "dControl.exe",
  "ConfigureDefender.exe",
  "PCHunter64_new.exe",
  "PowerRun_x64.exe",
  "PowerTool64_new.exe",
  "netscan.exe",
  "WinDefGpo_Reg.ps1",
  "def1.bat",
  "z.bat",
  "z1.bat",
  "clearlog.bat",
  "enable_dump_pass.reg",
  "VmManagedSetup.exe",
  "5541.exe",
  "ngrok.exe",
  "rustdesk.exe",
]);

const GENTLEMEN_EDR_KILLER_FILES = new Set([
  "eb.sys",
  "nseckrnl.sys",
  "GameDriverX64.sys",
  "stpm_old.sys",
  "stpm_new.sys",
  "dmx.sys",
  "360netmon_wfp.sys",
  "IMFForceDelete",
  "PoisonX",
]);

const GENTLEMEN_EDR_KILLER_NAMES = [
  "GentleKiller",
  "GentlemenCollection",
  "HexKiller",
  "ThrottleBlood",
  "HavocKiller",
  "OxideHarvest",
];

const GENTLEMEN_NETWORK_INDICATORS = [
  "176.120.22.127",
  "176.120.22[.]127",
  "2gkRUQNkJyaGkvuDziSq1RGIrwl_4bGyJtv6ez2Hk8Hrd5zvq",
  "2ozoAve91tpILCwKCbRDNz7us8e_2qLk1aLKZoV4Y6TfrcfjK",
];

const GLOBALPROTECT_0257_IPS = [
  "23.128.228.6",
  "23.128.228[.]6",
  "104.207.144.154",
  "104.207.144[.]154",
  "146.19.216.119",
  "146.19.216[.]119",
  "146.19.216.120",
  "146.19.216[.]120",
  "146.19.216.125",
  "146.19.216[.]125",
  "179.43.172.213",
  "179.43.172[.]213",
  "185.195.232.139",
  "185.195.232[.]139",
  "198.12.106.60",
  "198.12.106[.]60",
  "202.144.192.47",
  "202.144.192[.]47",
];

const GLOBALPROTECT_0257_CLIENT_VALUES = [
  "aa:bb:cc:dd:ee:ff",
  "00:11:22:33:44:55",
  "WINDOWS-LAPTOP-001",
  "DESKTOP-GP01",
  "GP-CLIENT",
];

const HEAVENS_GATE_EVASION_TERMS = [
  "Wow64Transition",
  "HeavensGate",
  "Heaven's Gate",
  "heavens gate",
  "WOW64 mode switch",
  "x86 to x64",
  "32-bit process",
  "64-bit shellcode",
];

const ARGAMAL_FILE_NAMES = new Set([
  "natives2_blob.bin",
  "zaesdl.dat",
]);

const ARGAMAL_NETWORK_INDICATORS = [
  "asper1.freeddns.org",
  "asper1[.]freeddns[.]org",
  "Winst0.kozow.com",
  "Winst0[.]kozow[.]com",
  "winst0.kozow.com",
  "winst0[.]kozow[.]com",
];

const LITELLM_AFFECTED_MIN = "1.74.2";
const LITELLM_FIXED = "1.83.7";
const STARLETTE_FIXED = "1.0.1";
const LITELLM_MCP_TEST_ROUTES = [
  "/mcp-rest/test/connection",
  "/mcp-rest/test/tools/list",
];
const LITELLM_CONFIG_TERMS = [
  "litellm",
  "LiteLLM",
  "LITELLM",
  "mcp-rest",
];
const AGENTJACKING_SENTRY_TERMS = [
  "sentry",
  "Sentry",
  "SENTRY_DSN",
  "sentry_dsn",
  "ingest.sentry.io",
];
const AGENTJACKING_MCP_TERMS = [
  "mcp",
  "MCP",
  "Model Context Protocol",
];
const AUTOJACK_AGENT_LOCALHOST_TERMS = [
  "AutoJack",
  "AutoGen Studio",
  "autogenstudio",
  "StdioServerParams",
  "server_params",
  "/api/mcp/ws",
  "localhost:8081",
  "127.0.0.1:8081",
  "b047730",
];

const OPERATION_HIGHLAND_SHA1_HASHES = loadHashSet("operation-highland-sha1.json");
const OPERATION_HIGHLAND_IOC_PATHS = [
  "/usr/share/man9/ph/.ph.man",
  "/usr/share/man9/ph",
  "/lib/systemd/system/chrom.service",
  "/etc/init.d/chrom",
  "/usr/bin/mlx",
  "/usr/bin/pnscan",
  "/usr/bin/stats",
  "/usr/bin/vlra",
  "/usr/lib/eth-scsi/libethscsi.so",
  "/usr/lib/psliba.so.7",
  "/usr/lib/psliba.so.7b",
  "/usr/lib/sslsh.ko",
  "/usr/sbin/.ssh.log",
  "/usr/sbin/auditdb",
  "/usr/sbin/land",
  "/usr/sbin/pnscan",
  "/usr/sbin/pscan",
  "/usr/share/nginx/cgi/cgi-bin/uptime",
  "/var/lib/sam",
];

const OPERATION_HIGHLAND_LOWER_CONFIDENCE_PATHS = new Set([
  "/usr/bin/mlx",
  "/usr/bin/pnscan",
  "/usr/bin/stats",
  "/usr/bin/vlra",
  "/usr/sbin/land",
  "/usr/sbin/pnscan",
  "/usr/sbin/pscan",
]);

const OPERATION_HIGHLAND_AUTH_FILES = [
  "/usr/bin/scp",
  "/usr/bin/sftp",
  "/usr/bin/ssh",
  "/usr/bin/ssh-keygen",
  "/usr/lib/security/pam_unix.so",
  "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
  "/usr/sbin/sshd",
  "/lib/security/pam_unix.so",
  "/lib/x86_64-linux-gnu/security/pam_unix.so",
];

const OPERATION_HIGHLAND_FILE_NAMES = new Set([
  ".ph.man",
  ".ssh.log",
  "auditdb",
  "chrom.service",
  "cln",
  "collect.sh",
  "land",
  "mlx",
  "p.sh",
  "pnscan",
  "pscan",
  "psliba.so.7",
  "psliba.so.7b",
  "sslsh.ko",
  "stats",
  "uudecode.pl",
  "uuencode.sh",
  "vlra",
]);

const OPERATION_HIGHLAND_NETWORK_INDICATORS = [
  "gs.thc.org",
  "gs.thc[.]org",
  "mobi.urgpt.dev",
  "mobi.urgpt[.]dev",
  "135.125.107.221",
  "135.125.107[.]221",
  "15.197.240.20",
  "15.197.240[.]20",
  "172.233.218.87",
  "172.233.218[.]87",
  "192.145.44.201",
  "192.145.44[.]201",
  "23.239.3.135",
  "23.239.3[.]135",
];

const OPERATION_HIGHLAND_TEXT_INDICATORS = [
  "Pamauth@123456",
  "/usr/share/man9/ph/.ph.man",
  "/usr/share/man9/ph/",
  "/usr/sbin/.ssh.log",
  "/usr/lib/eth-scsi/libethscsi.so",
  "/var/lib/sam",
  "/usr/sbin/auditdb",
  "/usr/share/nginx/cgi/cgi-bin/uptime",
  "fcgiwrap",
  "fastcgi_pass",
];

const OPERATION_HIGHLAND_PROCESS_MASQUERADE = [
  "[khubd]",
  "[kauditd] -sh",
  "smbd -D",
];

const PROVIDER_KEY_ENV_TERMS = [
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "AZURE_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "AWS_ACCESS_KEY_ID",
  "GOOGLE_API_KEY",
  "GEMINI_API_KEY",
  "MISTRAL_API_KEY",
  "COHERE_API_KEY",
];

const DEPENDENCY_FILE_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

const WATCH_FILE_NAMES = new Set([
  ...DEPENDENCY_FILE_NAMES,
  "requirements.txt",
  "pyproject.toml",
  "poetry.lock",
  "Pipfile",
  "Pipfile.lock",
  "uv.lock",
  "Dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  ".npmrc",
  ".pypirc",
  ".SRCINFO",
  "PKGBUILD",
  "splunk.version",
  "README.md",
  "SECURITY.md",
  ".gitignore",
  PEOPLESOFT_EXTORTION_MARKER,
  "psappsrv.cfg",
  "config.xml",
  "Review Past Due Doc.zip",
  "LicenseLoader.php",
  "install-persistent.php",
  "class-wc-subscription-trace-dispatch.php",
  "class-wc-subscription-diagnostics.php",
  "class-wc-subscription-scheduler.php",
  "cve_2026_55200_probe.c",
  "libpwn_cve_2026_55200_server.py",
  "libpwn_local_rce_harness.c",
  "libpwn_local_rce_exploit.py",
  "libpwn_rce_proof.txt",
  "2026-06-23-local-harness-output.txt",
  ...PEOPLESOFT_MESH_AGENT_FILES,
  "gentlemen.bmp",
  "README-GENTLEMEN.txt",
  "psexec.exe",
  ...GENTLEMEN_TOOLKIT_FILES,
  ...GENTLEMEN_EDR_KILLER_FILES,
  ...ARGAMAL_FILE_NAMES,
  ...OPERATION_HIGHLAND_FILE_NAMES,
  ...GLASSWASM_KNOWN_FILE_NAMES,
]);

const WATCH_FILE_EXTENSIONS = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".lock",
  ".md",
  ".py",
  ".php",
  ".pth",
  ".so",
  ".csv",
  ".txt",
  ".cfg",
  ".xml",
  ".log",
  ".jsp",
  ".bat",
  ".ps1",
  ".reg",
  ".cmd",
  ".vsix",
  ".wasm",
  ".bmp",
  ".env",
  ".tf",
  ".lnk",
  ".zip",
  ".msi",
  ".iso",
]);

const ASTRO_GITIGNORE_HIDE_FILES = [
  "branch_structure.json",
  "temp_auto_push.bat",
  "temp_interactive_push.bat",
];

const SQUIDBLEED_CONFIG_PATHS = [
  "/etc/squid/squid.conf",
  "/etc/squid3/squid.conf",
  "/usr/local/squid/etc/squid.conf",
];

const NGINX_CONFIG_ROOTS = [
  "/etc/nginx",
  "/usr/local/nginx/conf",
  "/opt/nginx",
];

const DIFY_FIXED = "1.14.2";
const DIFY_DEPLOYMENT_TERMS = [
  "DIFY",
  "dify",
  "langgenius/dify",
  "dify-api",
  "dify-web",
  "dify-worker",
  "dify-plugin-daemon",
];

const FFMPEG_PIXELSMASH_FIXED = "8.1.2";
const FFMPEG_PIXELSMASH_PACKAGES = [
  "ffmpeg",
  "libavcodec",
  "libavcodec-extra",
  "libavcodec-dev",
];

const FFMPEG_PIXELSMASH_TEXT_INDICATORS = [
  "PixelSmash",
  "CVE-2026-8461",
  "MagicYUV",
  "magicyuv",
  "VFS..D magicyuv",
  "ffmpeg -decoders",
  "ffprobe",
  "AVBuffer.free",
  "crafted MagicYUV AVI",
  "Jellyfin",
  "Nextcloud",
  "Movie preview",
  "PhotoPrism",
  "Immich",
  "ffmpegthumbnailer",
];

const LIBSSH2_CVE202655200_FIXED_COMMIT = "7acf3df";
const LIBSSH2_CVE202655200_AFFECTED_MAX = "1.11.1";
const LIBSSH2_CVE202655200_TEXT_INDICATORS = [
  "CVE-2026-55200",
  "CVE-2026-55199",
  "libssh2",
  "ssh2_transport_read",
  "packet_length",
  "out-of-bounds write",
  "OOB write",
  "SSH_MSG_EXT_INFO",
  "PR #2052",
  "pull/2052",
  "7acf3df",
  "97acf3dfda80c91c3a8c9f2372546301d4a1a7a8",
  "1762685",
];

const LIBSSH2_CVE202655200_POC_FILES = new Set([
  "cve_2026_55200_probe.c",
  "libpwn_cve_2026_55200_server.py",
  "libpwn_local_rce_harness.c",
  "libpwn_local_rce_exploit.py",
  "libpwn_rce_proof.txt",
  "2026-06-23-local-harness-output.txt",
]);

const LIBSSH2_CVE202655200_POC_TEXT_INDICATORS = [
  "bikini/exploitarium",
  "libssh2-cve-2026-55200-poc",
  "libssh2 CVE-2026-55200 PoC",
  "local RCE scaffold",
  "cve_2026_55200_probe.c",
  "libpwn_cve_2026_55200_server.py",
  "libpwn_local_rce_harness.c",
  "libpwn_local_rce_exploit.py",
  "LIBSSH2_PACKET_MAXPAYLOAD",
  "vulnerable32_allocation=19",
  "fixed32_decision=rejected",
  "RCE_PROOF=PASS",
  "libpwn-rce-verified",
];

const SHAPEDPLUGIN_KNOWN_HASHES = new Map([
  ["0e17c869d3e4586d4c160041042bd15123c2a37117a98a995fae885f0f4417fc", "ShapedPlugin LicenseLoader.php loader"],
]);

const SHAPEDPLUGIN_NETWORK_INDICATORS = [
  "account.shapedplugin.com",
  "account.shapedplugin[.]com",
  "194.76.217.28:2871",
  "194.76.217[.]28:2871",
  "generate.2faplugin.org",
  "generate[.]2faplugin[.]org",
];

const SHAPEDPLUGIN_TEXT_INDICATORS = [
  "ShapedPlugin",
  "Product Slider Pro for WooCommerce",
  "woo-product-slider-pro",
  "Real Testimonials Pro",
  "testimonial-pro",
  "Smart Post Show Pro",
  "smart-show-post-pro",
  "CVE-2026-10735",
  "CVE-2026-49777",
  "LicenseLoader.php",
  "TestimonialPRO.php",
  "install-persistent.php",
  "class-wc-subscription-trace-dispatch.php",
  "class-wc-subscription-diagnostics.php",
  "class-wc-subscription-scheduler.php",
  "woocommerce-subscription",
  "woocommerce-notification",
  "/wp-json/wc/v3/settings/apply",
  "theme_options_scripts",
  "wc_nf_install_done",
  "wp_2fa_totp_key",
  "wfls_2fa_secrets",
  "rsssl_totp_secret",
  "_two_factor_totp_key",
  "e268c35a06d85f672e70c9beecb4e5d1",
  "0e17c869d3e4586d4c160041042bd15123c2a37117a98a995fae885f0f4417fc",
];

const SHAPEDPLUGIN_FAKE_PLUGIN_PATHS = [
  "/wp-content/plugins/woocommerce-subscription",
  "/wp-content/plugins/woocommerce-notification",
];

const ARYSTINGER_IOC_PATHS = [
  "/tmp/bin/syswapd0",
  "/tmp/bin/syswapd0h",
  "/tmp/bin/syswapd0w",
  "/tmp/bin/dropbear",
  "/tmp/bin/dropbearkey",
  "/tmp/bin/nat_tunnel-linux-x86_64",
];

const ARYSTINGER_TEXT_INDICATORS = [
  "AryStinger",
  "Ary-Attack",
  "sh_#@!_2024_secret",
  "syswapd0",
  "syswapd0h",
  "syswapd0w",
  "hgodpcx.ajb8.com",
  "hgodpcx[.]ajb8[.]com",
  "hgodpcx.auq8.com",
  "hgodpcx[.]auq8[.]com",
  "io.ary2.com",
  "io[.]ary2[.]com",
  "opi7.com",
  "xook.ajb8.com",
  "xonice.ahb8.com",
  "eixfi.ajb8.com",
  "dybic.ajb8.com",
  "sdkv1.dataexplore.cc",
  "sdkv1.dataexplore.co",
  "107.150.106.14",
  "X-Executor-ID",
  "/auth",
  "/heartbeat",
  "/config",
  "/cmd",
  "ScriptWork",
  "DnsWork",
  "HttpAliveWork",
  "HttpScanWork",
  "DomainScanWrok",
  "IPScanWork",
  "CVE-2013-3307",
  "CVE-2016-5681",
  "CVE-2025-11837",
  "DIR-850L",
  "DIR-818LW",
  "DWR-118",
  "RTL819X",
];

const CLICKFIX_KB4_KNOWN_HASHES = new Map([
  ["7b7981c99d59595fe15377df84695bb72ce0b85560a3935f930657b2d162e5ef", "KnowBe4 ClickFix Review Past Due Doc ZIP"],
  ["adcd15f3d6b87f84d106ea426fa824fd20c9d64f6d199ce92580884290785f30", "KnowBe4 ClickFix RMM/MSI installer"],
  ["d7d2f0ee187549f3f4a114d716be12521fbf62d6d26e2ac23d2a32d521d08fd8", "KnowBe4 ClickFix password stealer"],
]);

const CLICKFIX_KB4_NETWORK_INDICATORS = [
  "document-auth.icu",
  "document-auth[.]icu",
  "italy-news.info",
  "italy-news[.]info",
  "lootrioya.info",
  "lootrioya[.]info",
];

const CLICKFIX_KB4_TEXT_INDICATORS = [
  "ClickFix",
  "Review Past Due Doc.zip",
  "Review Past Due Doc. zip",
  "urgent past due",
  "secure OneDrive attachment",
  "Win + R",
  "Win+R",
  "Run dialog",
  "clipboard stager",
  "DNS TXT",
  "PowerShell command directly into their clipboard",
  "RMM / MSI Installer",
  "Password Stealer",
  "7b7981c99d59595fe15377df84695bb72ce0b85560a3935f930657b2d162e5ef",
  "adcd15f3d6b87f84d106ea426fa824fd20c9d64f6d199ce92580884290785f30",
  "d7d2f0ee187549f3f4a114d716be12521fbf62d6d26e2ac23d2a32d521d08fd8",
];

function scanHost(options = {}) {
  const targetRoot = path.resolve(options.targetRoot || "/");
  const homePath = options.homePath || process.env.HOME || "";
  const findings = [];
  const osRelease = readOsRelease(readText(mapLinuxPath(targetRoot, "/etc/os-release")));
  const kernelRelease =
    options.kernelRelease ||
    readText(mapLinuxPath(targetRoot, "/proc/sys/kernel/osrelease")).trim();
  const architecture = options.architecture || detectArchitecture(targetRoot, kernelRelease);

  checkPlatform(findings, osRelease, kernelRelease);
  checkAlmaFragnesia(findings, osRelease, kernelRelease);
  checkItScapeArm64Kvm(findings, targetRoot, kernelRelease, architecture);
  checkKernelModules(findings, targetRoot);
  checkPersistence(findings, targetRoot, homePath);
  checkCompromisedNpmPackages(findings, targetRoot, homePath);
  checkAtomicArchAurCompromise(findings, targetRoot, homePath);
  checkDprkNpmRat(findings, targetRoot, homePath);
  checkDprkSocketIoLoader(findings, targetRoot, homePath);
  checkOtterCookieNpm(findings, targetRoot, homePath);
  checkEasyDayJsMastraNpm(findings, targetRoot, homePath);
  checkProcwireRoutecraftNpm(findings, targetRoot, homePath);
  checkWshuNetAndStitchSdkNpm(findings, targetRoot, homePath);
  checkMyraApintergrationpostNpm(findings, targetRoot, homePath);
  checkPostcssWindowsRatNpm(findings, targetRoot, homePath);
  checkSolanaFakeFix(findings, targetRoot, homePath);
  checkGlassWasmOpenVsx(findings, targetRoot, homePath);
  checkJetBrainsMarketplaceAiKeyStealers(findings, targetRoot, homePath);
  checkAstroConfigC2(findings, targetRoot, homePath);
  checkHadesPyPi(findings, targetRoot, homePath);
  checkDynatraceTeamPcpWatch(findings, targetRoot, homePath);
  checkPcpJackRelayArtifacts(findings, targetRoot, homePath);
  checkGentlemenRansomware(findings, targetRoot, homePath);
  checkHeavensGateEvasion(findings, targetRoot, homePath);
  checkArgamalGameRat(findings, targetRoot, homePath);
  checkCryptoClipperUsbWorm(findings, targetRoot, homePath);
  checkPeopleSoftCve202635273(findings, targetRoot, homePath);
  checkPaloAltoGlobalProtect0257(findings, targetRoot, homePath);
  checkRoundcubeCve202549113(findings, targetRoot, homePath);
  checkJoomlaJceCve202648907(findings, targetRoot, homePath);
  checkSplunkEnterpriseCve202620253(findings, targetRoot, homePath);
  checkRedcapExposure(findings, targetRoot, homePath);
  checkFortinetCredentialExposure(findings, targetRoot, homePath);
  checkClickFixKb4Phishing(findings, targetRoot, homePath);
  checkFfmpegPixelSmashExposure(findings, targetRoot, homePath);
  checkLibssh2Cve202655200Exposure(findings, targetRoot, homePath);
  checkShapedPluginSupplyChainCompromise(findings, targetRoot, homePath);
  checkSquidbleedFtpProxyExposure(findings, targetRoot, homePath);
  checkNginxCritical2026Exposure(findings, targetRoot, homePath);
  checkLiteLlmGatewayExposure(findings, targetRoot, homePath);
  checkDifyTapExposure(findings, targetRoot, homePath);
  checkOpenClawAgentExposure(findings, targetRoot, homePath);
  checkAgentjackingSentryMcpExposure(findings, targetRoot, homePath);
  checkAutoJackAgentLocalhostExposure(findings, targetRoot, homePath);
  checkNpmV12Readiness(findings, targetRoot, homePath);
  checkOperationHighlandAuthStack(findings, targetRoot, homePath);
  checkAryStingerEdgeProxy(findings, targetRoot, homePath);
  checkTransformersPayload(findings, targetRoot);
  checkSecretSurfaces(findings, targetRoot, homePath);

  return {
    tool: "linux-supply-chain-guard",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    targetRoot,
    host: {
      os: osRelease,
      kernelRelease,
      architecture: architecture || "unknown",
    },
    summary: summarize(findings),
    findings,
  };
}

function checkAstroConfigC2(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (isAstroConfigFileName(base)) {
      const hasCreateRequire = /\bcreateRequire\s*\(/i.test(text);
      const hasEvalSink = /\b(eval|Function)\s*\(/i.test(text);
      const hasNetworkLoader = /\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)|\bfrom\s+['"](?:node:)?https?['"]|\bhttps?\s*\.\s*(?:request|get)\s*\(|\bfetch\s*\(/i.test(text);
      const hasGlobalMutation = /global\s*(?:\.|\[)/i.test(text);
      const hasBlockchainRelay = /trongrid|aptoslabs|bsc-dataseed|publicnode|eth_getTransactionByHash|Sec-V|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP/i.test(text);
      const hasHiddenExecutableLine = text
        .split(/\r?\n/)
        .some((line) => line.length > 300 && /[ \t]{80,}\S/.test(line) && astroConfigLineHasLoaderSignal(line));

      if (hasCreateRequire && (hasEvalSink || hasNetworkLoader || hasGlobalMutation || hasBlockchainRelay)) {
        addFinding(findings, "critical", "astro-config-require-loader", "Astro config reconstructs require and also contains executable loader behavior.", relative, "Do not run astro dev/build/preview in this tree until the config diff and branch provenance are reviewed.");
      }
      if (hasNetworkLoader && hasEvalSink) {
        addFinding(findings, "critical", "astro-config-network-eval-loader", "Astro config combines network retrieval with eval/function execution behavior.", relative, "Treat any prior Astro build/dev/preview from this tree as potential payload execution and rotate exposed developer credentials from a clean posture.");
      }
      if (hasBlockchainRelay) {
        addFinding(findings, "warning", "astro-config-blockchain-c2-marker", "Astro config references blockchain/C2 relay markers reported in config-as-code supply-chain attacks.", relative, "Correlate with branch history, outbound network logs, and build/dev server execution.");
      }
      if (hasHiddenExecutableLine) {
        addFinding(findings, "warning", "astro-config-hidden-payload-line", "Astro config contains a long horizontally hidden executable-looking payload line.", relative, "Review the full line with wrapping disabled before running Astro commands.");
      }
    }

    if (base === ".gitignore") {
      for (const artifact of ASTRO_GITIGNORE_HIDE_FILES) {
        if (text.includes(artifact)) {
          addFinding(findings, "warning", "gitignore-hidden-pr-tooling", ".gitignore hides PR automation/helper artifact names reported with Astro config C2 injection.", `${relative}: ${artifact}`, "Review branch provenance and local ignored files before building or opening this repo in an agent.");
        }
      }
    }
  }
}

function checkPlatform(findings, osRelease, kernelRelease) {
  if (!osRelease.ID && !kernelRelease) {
    addFinding(findings, "review", "platform-not-linux-root", "Linux host metadata was not found.", "", "Run this tool on a Linux host root or mounted Linux filesystem.");
  }
}

function checkAlmaFragnesia(findings, osRelease, kernelRelease) {
  const distroId = String(osRelease.ID || "").toLowerCase();
  if (distroId !== "almalinux") {
    return;
  }

  const major = String(osRelease.VERSION_ID || "").split(".")[0];
  const patched = PATCHED_KERNELS[major];
  if (!patched) {
    addFinding(findings, "review", "alma-fragnesia-unknown-release", "AlmaLinux release is not in the built-in Fragnesia matrix.", `VERSION_ID=${osRelease.VERSION_ID || "unknown"}`, "Check vendor advisories for CVE-2026-46300 patched kernel guidance.");
    return;
  }

  if (!kernelRelease) {
    addFinding(findings, "review", "alma-fragnesia-kernel-unknown", "AlmaLinux host found but kernel release could not be read.", "", `Confirm the running kernel is ${patched} or newer for AlmaLinux ${major}.`);
    return;
  }

  if (compareKernelRelease(kernelRelease, patched) < 0) {
    addFinding(findings, "critical", "alma-fragnesia-vulnerable-kernel", "AlmaLinux kernel appears older than the Fragnesia patched kernel.", `${kernelRelease} < ${patched}`, "Patch the kernel and reboot, or apply vendor-approved temporary module mitigations until reboot is possible.");
  } else {
    addFinding(findings, "info", "alma-fragnesia-kernel-patched", "AlmaLinux kernel is at or above the built-in Fragnesia patched version.", `${kernelRelease} >= ${patched}`, "Keep following vendor advisories for later kernel updates.");
  }
}

function checkItScapeArm64Kvm(findings, targetRoot, kernelRelease, architecture) {
  if (!isArm64Architecture(architecture)) {
    return;
  }

  const modulesText = readText(mapLinuxPath(targetRoot, "/proc/modules"));
  const loaded = new Set(
    modulesText
      .split(/\r?\n/)
      .map((line) => line.split(/\s+/)[0])
      .filter(Boolean)
  );
  const loadedKvm = ["kvm", "kvm_arm", "kvm_arm64"].filter((name) => loaded.has(name));
  const kernelConfig = readKernelConfig(targetRoot, kernelRelease);
  const kvmConfigured = /\bCONFIG_KVM=(?:y|m)\b|\bCONFIG_KVM_ARM_HOST=(?:y|m)\b/i.test(kernelConfig);
  const itsConfigured = /\bCONFIG_ARM_GIC_V3_ITS=(?:y|m)\b|\bCONFIG_KVM_ARM_VGIC_V3=(?:y|m)\b/i.test(kernelConfig);

  if (loadedKvm.length === 0 && !kvmConfigured && !itsConfigured) {
    return;
  }

  const evidence = [`arch=${architecture}`];
  if (loadedKvm.length > 0) evidence.push(`loaded KVM modules: ${loadedKvm.join(", ")}`);
  if (kvmConfigured) evidence.push("KVM enabled in kernel config");
  if (itsConfigured) evidence.push("ARM GIC/vGIC ITS support visible in kernel config");

  addFinding(findings, "warning", "itscape-arm64-kvm-exposure", "ARM64 KVM host exposure matches the ITScape / CVE-2026-46316 risk lane.", evidence.join("; "), "Patch to a vendor-fixed kernel, reboot affected hypervisors, and limit untrusted guest workloads until vendor backport status is confirmed.");

  if (!kernelRelease) {
    addFinding(findings, "review", "itscape-arm64-kvm-kernel-unknown", "ARM64 KVM exposure found but kernel release could not be read.", `arch=${architecture}`, "Confirm whether the running kernel includes the CVE-2026-46316 / ITScape fix or a vendor backport.");
    return;
  }

  if (compareKernelRelease(kernelRelease, ITSCAPE_UPSTREAM_FIXED_KERNEL) < 0) {
    addFinding(findings, "review", "itscape-arm64-kvm-kernel-review", "ARM64 KVM kernel is older than the upstream ITScape fix baseline.", `${kernelRelease} < ${ITSCAPE_UPSTREAM_FIXED_KERNEL}`, "Do not rely on upstream version alone for distro kernels: verify vendor advisory/backport status for CVE-2026-46316 and reboot into the fixed kernel.");
  } else {
    addFinding(findings, "info", "itscape-arm64-kvm-upstream-patched", "ARM64 KVM kernel is at or above the upstream ITScape fix baseline.", `${kernelRelease} >= ${ITSCAPE_UPSTREAM_FIXED_KERNEL}`, "Keep following distro/cloud advisories for CVE-2026-46316 and related ARM64 KVM hardening updates.");
  }
}

function checkKernelModules(findings, targetRoot) {
  const modulesText = readText(mapLinuxPath(targetRoot, "/proc/modules"));
  const modprobeDir = mapLinuxPath(targetRoot, "/etc/modprobe.d");
  if (!modulesText && !exists(modprobeDir)) {
    return;
  }

  const loaded = new Set(
    modulesText
      .split(/\r?\n/)
      .map((line) => line.split(/\s+/)[0])
      .filter(Boolean)
  );
  const risky = ["esp4", "esp6", "rxrpc"].filter((name) => loaded.has(name));
  if (risky.length > 0) {
    addFinding(findings, "warning", "fragnesia-risk-modules-loaded", "Fragnesia-related kernel modules are currently loaded.", risky.join(", "), "If these modules are not required for IPsec ESP or AFS/rxrpc workloads, apply vendor-approved mitigations and patch/reboot.");
  }

  const modprobeText = readDirectoryText(modprobeDir);
  const missing = ["esp4", "esp6", "rxrpc"].filter((name) => {
    const pattern = new RegExp(`install\\s+${escapeRegExp(name)}\\s+/bin/false`);
    return !pattern.test(modprobeText);
  });
  if (missing.length > 0) {
    addFinding(findings, "review", "fragnesia-module-blacklist-not-confirmed", "Temporary Fragnesia module blacklist was not fully confirmed.", `missing install /bin/false entries: ${missing.join(", ")}`, "This is only a mitigation check. Prefer patched kernels and reboot when available.");
  }
}

function checkPersistence(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const candidates = [
    "/etc/systemd/system/pgsql-monitor.service",
    "/usr/bin/pgmonitor.py",
    "/tmp/transformers.pyz",
    homeRelative ? `${homeRelative}/.config/systemd/user/gh-token-monitor.service` : "",
    homeRelative ? `${homeRelative}/.local/bin/gh-token-monitor.sh` : "",
    homeRelative ? `${homeRelative}/.config/gh-token-monitor` : "",
    homeRelative ? `${homeRelative}/.config/systemd/user/pgsql-monitor.service` : "",
    homeRelative ? `${homeRelative}/.local/bin/pgmonitor.py` : "",
  ].filter(Boolean);

  for (const candidate of candidates) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      addFinding(findings, "critical", "known-supply-chain-persistence-path", "Known supply-chain persistence or payload path exists.", candidate, "Contain the host and preserve evidence. Remove persistence from a trusted recovery posture before rotating tokens.");
    }
  }
}

function checkDprkNpmRat(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    for (const packageName of KNOWN_DPRK_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "dprk-npm-rat-package-reference", "Known DPRK npm RAT package name appears in dependency metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. Inspect from a clean posture and rotate credentials if execution is suspected.");
      }
    }
    for (const indicator of DPRK_NPM_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "dprk-npm-rat-text-indicator", "DPRK npm RAT behavior indicator appears in dependency metadata.", `${relative}: ${indicator}`, "Review the referenced package scripts and lockfile entries before running package manager commands.");
      }
    }
  }
}

function checkDprkSocketIoLoader(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    if (isDocumentationPath(relative)) continue;
    if (hasDprkSocketIoLoaderShape(text)) {
      addFinding(findings, "critical", "dprk-socketio-loader-behavior", "DPRK/Famous Chollima-style Socket.IO npm loader behavior appears in scanned code.", `${relative}: socket.io + /api/service + 0001.dat`, "Do not run npm install/build/test in this tree. Preserve the package, inspect from a clean posture, and rotate developer/browser/package credentials if execution is suspected.");
    }
  }
}

function checkCompromisedNpmPackages(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    for (const packageName of KNOWN_COMPROMISED_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "compromised-npm-package-reference", "Known compromised npm package appears in dependency metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. Isolate affected systems if execution is suspected and rotate secrets from a clean posture.");
      }
    }
  }
}

function checkAtomicArchAurCompromise(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/tmp",
    "/var/tmp",
    "/var/cache",
    "/var/lib/pacman/local",
    "/opt",
    "/srv",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text || !text.includes(ATOMIC_ARCH_AUR_PACKAGE)) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const base = path.basename(filePath);
    const isAurBuildFile = base === "PKGBUILD" || base === ".SRCINFO" || base.endsWith(".install");

    if (isAurBuildFile) {
      addFinding(findings, "critical", "atomicarch-aur-atomic-lockfile-reference", "AUR build metadata references the malicious atomic-lockfile npm package.", `${relative}: ${ATOMIC_ARCH_AUR_PACKAGE}`, "Do not build or install this AUR package. Preserve the PKGBUILD/install hook, remove the package from any build queue, and rotate developer credentials if it may have executed.");
    }

    if (isAurBuildFile && /\b(?:npm\s+(?:install|i|exec|x)|npx)\b/i.test(text)) {
      addFinding(findings, "critical", "atomicarch-aur-npm-loader", "AUR build/install script invokes npm while referencing atomic-lockfile.", relative, "Treat as AtomicArch/IronWorm-style AUR supply-chain compromise. If installed, isolate the host and rotate GitHub, npm, SSH, Vault, Docker/Podman, browser, and chat credentials from a clean machine.");
    }

    if (/eBPF|rootkit|\bdeps\b|browser cookies?|Vault|Docker|Podman|Slack|Discord|Teams/i.test(text)) {
      addFinding(findings, "warning", "atomicarch-payload-text-indicator", "AtomicArch/IronWorm payload behavior terms appear near atomic-lockfile.", relative, "Correlate with AUR install history, npm cache, package build artifacts, process/module state, and credential exposure.");
    }
  }
}

function checkOtterCookieNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of OTTERCOOKIE_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "ottercookie-npm-package-reference", "Panther OtterCookie npm campaign package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. If install occurred, inspect for Vercel C2 traffic, SSH authorized_keys modification, and rotate developer secrets from a clean posture."); // push-guard: ignore
      }
    }

    for (const indicator of OTTERCOOKIE_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "ottercookie-text-indicator", "OtterCookie npm behavior or C2 indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with npm install history, outbound traffic, shell history, ~/.ssh/authorized_keys, and firewall changes before cleanup."); // push-guard: ignore
      }
    }
  }
}

function checkEasyDayJsMastraNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const indicator of EASY_DAY_JS_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "easy-day-js-mastra-indicator", "OX easy-day-js / Mastra npm supply-chain indicator appears in dependency metadata.", `${relative}: ${indicator}`, "Do not run npm install/build/test in this tree. If install may have occurred, review OX guidance and treat crypto-wallet activity as exposed until checked.");
      }
    }
  }
}

function checkProcwireRoutecraftNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findDependencyFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const indicator of PROCWIRE_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "procwire-routecraft-windows-dropper-indicator", "SafeDep procwire / routecraft Windows npm dropper indicator appears in dependency metadata.", `${relative}: ${indicator}`, "Do not run npm install/build/test in this tree. If this was installed on Windows, inspect temp updater-named executables, preserve evidence, and rotate credentials from a clean posture if execution may have occurred.");
      }
    }
  }
}

function checkWshuNetAndStitchSdkNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of WSHU_NET_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "wshu-net-npm-package-reference", "SafeDep WSHU npm credential-stealer package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run package manager commands in this tree. If install may have occurred, inspect user systemd persistence and rotate developer, browser, cloud, package, and wallet credentials from a clean posture.");
      }
    }

    for (const indicator of WSHU_NET_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "wshu-net-npm-indicator", "SafeDep WSHU npm infostealer indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with npm install timing, user systemd services, ~/.local/bin daemon names, outbound Telegram API traffic, and credential exposure before cleanup.");
      }
    }

    for (const indicator of STITCH_SDK_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "withgoogle-stitch-sdk-indicator", "SafeDep @withgoogle/stitch-sdk scope-squat credential-harvester indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Treat Claude Code, Git, GitHub CLI, npm, SSH, and Docker credential surfaces as exposed if the package or CLI ran.");
      }
    }
  }
}

function checkMyraApintergrationpostNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/usr/local/lib",
    "/etc/profile.d",
  ].filter(Boolean);

  for (const candidate of MYRA_HOST_ARTIFACTS) {
    if (exists(mapLinuxPath(targetRoot, candidate))) {
      addFinding(findings, "critical", "myra-linux-rat-artifact-path", "MYRA/apintergrationpost Linux RAT/rootkit artifact path exists.", candidate, "Contain the host and preserve evidence. Recover from trusted media before rotating secrets or returning the host to service.");
    }
  }

  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of MYRA_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "myra-apintergrationpost-package-reference", "SafeDep MYRA/apintergrationpost npm RAT package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. Version 4.0.2 and later forced root execution in reporting; preserve artifacts and investigate as host compromise if execution occurred.");
      }
    }

    for (const indicator of MYRA_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "myra-apintergrationpost-indicator", "MYRA/apintergrationpost Linux RAT/rootkit indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Inspect for native rootkit artifacts, memfd execution, profile.d persistence, and C2 traffic before any cleanup.");
      }
    }
  }
}

function checkPostcssWindowsRatNpm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of POSTCSS_WINDOWS_RAT_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "postcss-windows-rat-package-reference", "JFrog PostCSS typosquat Windows RAT package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. If installed on Windows, inspect temp winPatch artifacts, Run-key persistence, Python loader files, and C2 traffic.");
      }
    }

    for (const indicator of POSTCSS_WINDOWS_RAT_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "postcss-windows-rat-indicator", "JFrog PostCSS typosquat Windows RAT indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with Windows runner or workstation install history and preserve package cache/lockfile evidence.");
      }
    }
  }
}

function checkSolanaFakeFix(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/usr/local/lib/python3",
    "/usr/lib/python3",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const packageName of SOLANA_FAKEFIX_NPM_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "solana-fakefix-npm-package-reference", "JFrog Solana FakeFix / CMS loader npm package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not run npm install/build/test in this tree. If install/import occurred, rotate Solana wallets, SSH keys, cloud credentials, source-control tokens, npm tokens, and CI secrets from a clean posture.");
      }
    }

    for (const packageName of SOLANA_FAKEFIX_PYPI_PACKAGES) {
      if (pythonPackageNameInText(text, packageName)) {
        addFinding(findings, "critical", "solana-fakefix-pypi-package-reference", "JFrog Solana FakeFix PyPI package appears in scanned metadata.", `${relative}: ${packageName}`, "Do not import this package or run Python package-manager commands in this environment. If import occurred, rotate Solana wallets, SSH keys, cloud credentials, source-control tokens, PyPI tokens, and CI secrets from a clean posture.");
      }
    }

    for (const indicator of SOLANA_FAKEFIX_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "solana-fakefix-text-indicator", "Solana FakeFix / CMS loader behavior indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with package metadata, npm/PyPI install history, shell profiles, cron, LaunchAgents, Registry/Run-key equivalents, and network telemetry before cleanup.");
      }
    }
  }
}

function checkGlassWasmOpenVsx(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/usr/local/share",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const base = path.basename(filePath);

    if (base === "snqpkebiwrxmoivl.wasm" || base === "orybbbdsuqmaapel.wasm") {
      addFinding(findings, "critical", "glasswasm-openvsx-wasm-payload-file", "GlassWASM Open VSX WASM payload filename exists.", relative, "Remove the affected extension/source and treat any activated editor host as arbitrary code execution until reviewed.");
    }
    if (/^(?:exargd\.vsblack-0\.0\.1|noellee-doc\.flint-debug-0\.1\.1)\.vsix$/i.test(base)) {
      addFinding(findings, "critical", "glasswasm-openvsx-vsix-file", "Known GlassWASM Open VSX trojanized VSIX filename exists.", relative, "Do not install or activate this extension. Preserve the file for hash verification and incident response.");
    }

    const text = readText(filePath);
    if (!text) continue;

    for (const packageName of GLASSWASM_OPENVSX_PACKAGES) {
      if (text.includes(packageName)) {
        addFinding(findings, "critical", "glasswasm-openvsx-package-reference", "Socket GlassWASM Open VSX affected extension appears in scanned metadata.", `${relative}: ${packageName}`, "Remove Open VSX-sourced copies and treat prior activation as potential second-stage execution.");
      }
    }

    for (const indicator of GLASSWASM_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "glasswasm-openvsx-text-indicator", "GlassWASM Open VSX IOC or C2 dead-drop marker appears in scanned text.", `${relative}: ${indicator}`, "Correlate with editor extension install source, extension host process logs, Solana RPC traffic, and child-process execution.");
      }
    }

    if (hasGlassWasmLoaderShape(text)) {
      addFinding(findings, "critical", "glasswasm-openvsx-loader-shape", "Editor/package code combines WASM loading with GlassWASM-style C2 or child-process execution behavior.", relative, "Do not activate this extension/package. Inspect the WASM and JavaScript loader, then rotate developer credentials if activation occurred.");
    } else if (hasTinyGoWasmHostShape(text)) {
      addFinding(findings, "warning", "tinygo-wasm-js-host-review", "TinyGo/WebAssembly JavaScript host fingerprints appear in scanned code.", relative, "Review why this package or extension ships WASM and whether it can reach Node APIs or spawn child processes.");
    }
  }
}

function checkJetBrainsMarketplaceAiKeyStealers(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/usr/local/share",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const normalizedPath = relative.toLowerCase();
    const text = readText(filePath);
    const haystack = `${normalizedPath}\n${text || ""}`;

    for (const pluginId of JETBRAINS_AI_KEY_PLUGIN_IDS) {
      if (haystack.includes(pluginId)) {
        addFinding(findings, "critical", "jetbrains-marketplace-ai-key-plugin-reference", "Aikido-reported malicious JetBrains Marketplace plugin ID appears in scanned host metadata.", `${relative}: ${pluginId}`, "Remove the plugin from JetBrains IDEs from a trusted posture, preserve plugin files for review, and rotate AI/provider/API keys if the plugin may have loaded.");
      }
    }

    if (!text) continue;
    for (const indicator of JETBRAINS_AI_KEY_ENDPOINT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "jetbrains-marketplace-ai-key-exfil-indicator", "JetBrains Marketplace AI-key stealer exfiltration indicator appears in scanned text.", `${relative}: ${indicator}`, "Correlate with JetBrains plugin install history and outbound logs, then rotate exposed AI/provider/API keys from a clean posture if execution is suspected.");
      }
    }
  }
}

function checkHadesPyPi(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const runtimePaths = [
    joinParts("/tmp/.bun", "_ran"),
    "/tmp/b.zip",
    "/tmp/b/bun",
    joinParts("/tmp/.sshu", "-setup.js"),
    joinParts("/var/tmp/.bun", "_ran"),
    "/var/tmp/b.zip",
    "/var/tmp/b/bun",
  ];
  for (const runtimePath of runtimePaths) {
    if (exists(mapLinuxPath(targetRoot, runtimePath))) {
      addFinding(findings, "warning", "hades-runtime-artifact-path", "Hades Bun/SSH runtime artifact path exists.", runtimePath, "Preserve evidence before cleanup. If package execution is suspected, isolate the host and rotate developer/package/cloud credentials from a clean posture.");
    }
  }

  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib",
    "/usr/lib/python3",
    "/usr/lib64/python3",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findHadesFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const base = path.basename(filePath);
    if (/-setup\.pth$/i.test(base)) {
      addFinding(findings, "warning", "hades-pth-startup-hook-file", "Hades-style Python startup hook filename appears in scanned host tree.", relative, "Review the .pth file before starting Python in this environment. Executable .pth lines can run on Python startup.");
    }
    if (base === "_index.js" && /site-packages|\.venv|\/venv\/|\.dist-info|\.whl|py3-none-any/i.test(relative)) {
      addFinding(findings, "warning", "hades-python-payload-filename", "Hades-style _index.js payload filename appears in a Python package context.", relative, "Treat this environment as suspicious until the package provenance and payload content are reviewed.");
    }
    if (HADES_NATIVE_EXTENSION_FILES.has(base)) {
      addFinding(findings, "critical", "hades-known-native-extension", "Native extension filename reported in Hades PyPI artifacts exists.", relative, "Contain the environment and preserve the wheel/site-packages directory for incident response.");
    } else if (base.endsWith(".abi3.so") && exists(path.join(path.dirname(filePath), "_index.js"))) {
      addFinding(findings, "warning", "hades-native-extension-payload-pair", "Python native extension is paired with _index.js.", relative, "Review for Hades-style import-time JavaScript launcher behavior before importing the package.");
    }

    const text = readText(filePath);
    if (!text) continue;
    for (const [packageName, versions] of Object.entries(HADES_PYPI_PACKAGES)) {
      for (const version of versions) {
        if (pythonPackageVersionInText(text, packageName, version)) {
          addFinding(findings, "critical", "hades-pypi-package-version", "Known Hades PyPI package version appears in scanned metadata.", `${relative}: ${packageName}==${version}`, "Do not run Python/package-manager commands in this environment. Pin away from the affected version and rotate credentials if execution may have occurred.");
        }
      }
    }
    if (isHadesPthBunLoader(text)) {
      addFinding(findings, "critical", "hades-pth-bun-loader", "Executable Python startup hook appears to bootstrap Bun and launch _index.js.", relative, "Treat Python startup in this environment as possible payload execution. Preserve artifacts and rotate exposed credentials from a clean machine.");
    }
    if (/sys\.path/i.test(text) && /_index\.js/i.test(text) && /bun|subprocess/i.test(text)) {
      addFinding(findings, "critical", "hades-syspath-payload-loader", "Python code searches sys.path for _index.js and attempts Bun/subprocess execution.", relative, "Review for the Hades loader/payload split before running Python or package tools.");
    }
    if (
      base === "_index.js" &&
      /(?:unrestricted\s+mode|safety\s+guidelines|guardrails)/i.test(text) &&
      /(?:biological|nuclear)\s+weapons?/i.test(text)
    ) {
      addFinding(findings, "warning", "hades-llm-anti-analysis-bait", "Hades-style LLM refusal-bait appears in a Python package JavaScript payload.", relative, "Do not feed the raw payload to an LLM triage flow. Use static extraction, YARA, deobfuscation, and behavioral review from a clean posture.");
    }
    for (const indicator of HADES_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "hades-text-indicator", "Hades PyPI campaign indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with installed package versions, Python startup hooks, CI artifacts, and credential exposure.");
      }
    }
  }
}

function checkDynatraceTeamPcpWatch(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local/lib/node_modules",
    "/etc",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const tokenMatches = Array.from(new Set(text.match(DYNATRACE_TOKEN_PATTERN) || []));
    for (const token of tokenMatches) {
      addFinding(findings, "critical", "dynatrace-token-exposure", "Dynatrace token-shaped credential appears in scanned metadata.", `${relative}: ${redactDynatraceToken(token)}`, "Treat as a credential exposure. Rotate the token from a clean posture, review scopes, and audit Dynatrace/API usage around the exposure window.");
    }

    for (const term of DYNATRACE_TEAMPCP_REPO_TERMS) {
      if (text.includes(term)) {
        addFinding(findings, "warning", "dynatrace-teampcp-repo-term", "TeamPCP/Dynatrace screenshot repo term appears in scanned metadata.", `${relative}: ${term}`, "Weak signal only: preserve the file, identify whether the term belongs to an expected Dynatrace-controlled source, and correlate with package, CI, and repository access logs.");
      }
    }

    for (const term of DYNATRACE_TEAMPCP_SERVICE_TERMS) {
      if (text.includes(term)) {
        addFinding(findings, "warning", "dynatrace-teampcp-service-term", "TeamPCP/Dynatrace screenshot service term appears in scanned metadata.", `${relative}: ${term}`, "Weak signal only: correlate with repository visibility, CI logs, package metadata, and token rotation status. This finding does not prove compromise by itself.");
      }
    }
  }
}

function checkPcpJackRelayArtifacts(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const candidatePaths = [
    "/var/tmp/.xs",
    "/tmp/.ch",
    "/tmp/.ch2",
    "/tmp/.ch3",
    "/tmp/.ch4",
    "/tmp/.ch5",
    "/etc/systemd/system/xsync.service",
    "/root/.sliver-client/configs/root_localhost.cfg",
    "/root/excalibur/smtp_proxies.csv",
    homeRelative ? `${homeRelative}/.config/systemd/user/xsync.service` : "",
  ].filter(Boolean);

  for (const candidate of candidatePaths) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      addFinding(findings, "warning", "pcpjack-relay-artifact-path", "PCPJack/Chisel SMTP relay artifact path exists.", candidate, "Review for Sliver/Chisel relay persistence. Preserve evidence and inspect cron/systemd before cleanup.");
    }
  }

  const cronText = [
    readText(mapLinuxPath(targetRoot, "/etc/crontab")),
    readDirectoryText(mapLinuxPath(targetRoot, "/etc/cron.d")),
    homeRelative ? readDirectoryText(mapLinuxPath(targetRoot, `${homeRelative}/.config/systemd/user`)) : "",
    homeRelative ? readDirectoryText(mapLinuxPath(targetRoot, `${homeRelative}/.local/share/systemd/user`)) : "",
  ].join("\n");
  if (/#\s*xsync\b|\bxsync\b.*\/var\/tmp\/\.xs|\/var\/tmp\/\.xs.*\bxsync\b/i.test(cronText)) {
    addFinding(findings, "warning", "pcpjack-xsync-persistence-marker", "xsync persistence marker references the PCPJack /var/tmp/.xs Chisel relay path.", "xsync + /var/tmp/.xs", "Review cron and systemd user services for Chisel relay watchdog persistence.");
  }

  const roots = [
    homeRelative,
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    if (PCPJACK_FILE_NAMES.has(path.basename(filePath))) {
      addFinding(findings, "warning", "pcpjack-relay-file-name", "PCPJack/Chisel relay file name appears in scanned host tree.", relative, "Review this file for SMTP relay, Sliver, Chisel, or proxy fleet state.");
    }
    const text = readText(filePath);
    if (!text) continue;
    for (const indicator of PCPJACK_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "pcpjack-relay-text-indicator", "PCPJack/Chisel SMTP relay indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with process, cron, systemd, Sliver, and outbound SMTP relay logs.");
      }
    }
  }
}

function checkGentlemenRansomware(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/mnt",
    "/media",
    "/ProgramData",
    "/Users",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const baseLower = base.toLowerCase();
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const size = fileSizeBytes(filePath);

    if (baseLower === "gentlemen.bmp" || base === "README-GENTLEMEN.txt") {
      addFinding(findings, "critical", "gentlemen-ransomware-note-wallpaper", "Gentlemen ransomware ransom-note or wallpaper filename exists.", relative, "Treat this as a high-confidence ransomware artifact. Isolate the host, preserve timestamps and file metadata, and review clean backups before any cleanup.");
    }

    if (GENTLEMEN_TOOLKIT_FILES.has(base)) {
      addFinding(findings, "warning", "gentlemen-toolkit-file-name", "Gentlemen exposed operator-toolkit filename exists.", relative, "Review for staged defense-evasion, remote-access, network-scan, or credential-dump tooling. Preserve evidence before deleting files.");
    }

    if (relative.includes("/GentlemenCollection/")) {
      addFinding(findings, "warning", "gentlemen-edr-killer-staging-directory", "Gentlemen EDR-killer staging directory appears in scanned host tree.", relative, "Review for GentleKiller, HexKiller, ThrottleBlood, HavocKiller, BYOVD driver drops, and sudden shutdown of protected security processes.");
    }

    if (isGentlemenEdrKillerFileName(base)) {
      addFinding(findings, "warning", "gentlemen-edr-killer-file-name", "ESET-reported Gentlemen EDR-killer variant or abused driver filename exists.", relative, "Correlate with Gentlemen ransomware activity, vulnerable-driver block events, service-control logs, and EDR process termination telemetry.");
    }

    if (baseLower === "psexec.exe") {
      addFinding(findings, "review", "gentlemen-psexec-dropper-name", "PsExec filename appears in a scanned host or mounted-root tree.", relative, "PsExec can be legitimate. Correlate with Gentlemen spread flags, remote execution logs, and surrounding toolkit files before treating it as malicious.");
    }

    if (shouldHashGentlemenArtifact(base) && size > 0 && size <= 100 * 1024 * 1024) {
      const digest = sha256File(filePath);
      const label = GENTLEMEN_KNOWN_HASHES.get(digest);
      if (label) {
        addFinding(findings, "critical", "gentlemen-known-hash", "Known Gentlemen ransomware-related SHA-256 observed.", `${relative}: ${label}; sha256=${digest}`, "Contain the host and preserve the file for incident response. Do not execute the file.");
      }
    }

    const text = size <= 1024 * 1024 ? readText(filePath) : "";
    if (!text) continue;

    if (/\bgentlemen_system\b|LOCKER_BACKGROUND=1|README-GENTLEMEN\.txt|gentlemen\.bmp|\b(?:UpdateSystem|UpdateUser|GupdateS|GupdateU)\b/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-encryptor-runtime-marker", "Gentlemen ransomware runtime marker appears in scanned host metadata.", relative, "Review process, service, scheduled-task, wallpaper, ransom-note, and filesystem activity around this path.");
    }

    if (/\bpsexec(?:\.exe)?\b[\s\S]{0,240}(?:--spread|--ip|--login|--password)|(?:--spread|--ip|--login|--password)[\s\S]{0,240}\bpsexec(?:\.exe)?\b/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-self-propagation-marker", "Gentlemen-style PsExec self-propagation marker appears in scanned text.", relative, "Correlate with Windows event logs, SMB/admin-share access, command history, and lateral-movement evidence.");
    }

    if (/(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+\/set|wevtutil\s+cl|cipher\s+\/w|taskkill\b|sc\s+stop\b|net\s+stop\b|dControl\.exe|ConfigureDefender\.exe|PCHunter64_new\.exe|PowerTool64_new\.exe|WinDefGpo_Reg\.ps1|enable_dump_pass\.reg)/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-defense-evasion-command-marker", "Gentlemen toolkit or ransomware defense-evasion command marker appears in scanned text.", relative, "Review whether this is approved administration, attacker staging, or ransomware pre-encryption activity.");
    }

    for (const indicator of GENTLEMEN_EDR_KILLER_NAMES) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "gentlemen-edr-killer-suite-marker", "Gentlemen EDR-killer suite marker appears in scanned host metadata.", `${relative}: ${indicator}`, "Review for operator-provided GentleKiller tooling, BYOVD driver abuse, fake version/signature metadata, packers, and kernel-level security process termination.");
      }
    }

    if (/\bGentle(?:men|Killer)\b[\s\S]{0,360}\b(?:BYOVD|bring your own vulnerable driver|vulnerable driver|kernel(?:-level)?|invalid digital signatures?|copied legitimate certificates?|fake version|Enigma|Themida|security processes?)\b/i.test(text)
      || /\b(?:BYOVD|bring your own vulnerable driver|vulnerable driver|kernel(?:-level)?|invalid digital signatures?|copied legitimate certificates?|fake version|Enigma|Themida|security processes?)\b[\s\S]{0,360}\bGentle(?:men|Killer)\b/i.test(text)) {
      addFinding(findings, "warning", "gentlemen-edr-killer-byovd-marker", "Gentlemen/GentleKiller BYOVD or binary-impersonation behavior appears in scanned host metadata.", relative, "Block known-vulnerable drivers, alert on protected security process termination, and preserve suspected EDR-killer binaries for analysis.");
    }

    for (const indicator of GENTLEMEN_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "gentlemen-network-indicator", "Gentlemen ransomware campaign network or session indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with firewall, proxy, EDR, and remote-access logs. Preserve evidence and rotate credentials from a clean posture if compromise is confirmed.");
      }
    }
  }
}

function checkHeavensGateEvasion(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/mnt",
    "/media",
    "/ProgramData",
    "/Users",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const size = fileSizeBytes(filePath);
    if (size <= 0 || size > 1024 * 1024) continue;
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    const matched = HEAVENS_GATE_EVASION_TERMS.filter((term) => text.toLowerCase().includes(term.toLowerCase()));
    const hasModeSwitchContext = /wow64|syswow64|32-bit|x86|64-bit|x64/i.test(text)
      && /shellcode|injection|inject|syscall|edr|evasion|bypass|malware|ransomware|payload|process hollow/i.test(text);
    const hasTransitionMarker = /Wow64Transition|HeavensGate|Heaven's Gate|heavens gate/i.test(text)
      && /(?:selector|segment|cs)\s*0x33|far\s+(?:jump|call|return)|\bretf\b/i.test(text);
    if (matched.length > 0 && hasModeSwitchContext && hasTransitionMarker) {
      addFinding(findings, "review", "heavens-gate-wow64-evasion-marker", "Heaven's Gate-style WOW64 mode-switching evasion terms appear in scanned metadata.", `${relative}: ${matched.slice(0, 3).join(", ")}`, "Review as a malware-analysis lead only. Correlate with EDR telemetry, memory scans, suspicious 32-bit processes launching 64-bit execution, and endpoint containment state.");
    }
  }
}

function checkArgamalGameRat(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/mnt",
    "/media",
    "/ProgramData",
    "/Users",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const baseLower = base.toLowerCase();
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const size = fileSizeBytes(filePath);

    if (ARGAMAL_FILE_NAMES.has(baseLower)) {
      addFinding(findings, "warning", "argamal-game-rat-file-name", "Argamal game-RAT artifact filename exists.", relative, "Review whether this came from an adult-game archive or torrent download. Preserve the surrounding archive/extract path before cleanup.");
    }

    const text = size <= 1024 * 1024 ? readText(filePath) : "";
    if (!text) continue;

    for (const indicator of ARGAMAL_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "argamal-game-rat-network-indicator", "Argamal RAT network indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with DNS, proxy, firewall, and scheduled-task logs. Isolate the host if execution is suspected.");
      }
    }

    if (/bitsadmin(?:\.exe)?\b[\s\S]{0,300}zaesdl\.dat|zaesdl\.dat[\s\S]{0,300}bitsadmin(?:\.exe)?\b/i.test(text)) {
      addFinding(findings, "warning", "argamal-game-rat-bitsadmin-stage", "Argamal-style delayed bitsadmin second-stage fetch marker appears in scanned text.", relative, "Review scheduled tasks, BITS jobs, and GitHub download history for delayed payload retrieval.");
    }

    if (/(?:Windows Color System Calibration Loader|Color System Calibration|WcsPlugInService|ICM calibration|COM hijack|COM hijacking)/i.test(text)) {
      addFinding(findings, "warning", "argamal-game-rat-com-hijack-marker", "Argamal-style Windows Color System COM-hijack persistence term appears in scanned text.", relative, "Review HKCU/HKLM COM registration keys, logon persistence, and user-profile registry hives from a clean posture.");
    }

    if (/(?:Sandboxie|Procmon64|Process Monitor)[\s\S]{0,220}(?:PowerShell|zaesdl\.dat|natives2_blob\.bin|Argamal)|(?:PowerShell|zaesdl\.dat|natives2_blob\.bin|Argamal)[\s\S]{0,220}(?:Sandboxie|Procmon64|Process Monitor)/i.test(text)) {
      addFinding(findings, "warning", "argamal-game-rat-anti-analysis-marker", "Argamal-style anti-analysis check terms appear near loader behavior.", relative, "Treat as suspicious loader logic until proven benign; review in isolation and do not launch the game executable.");
    }
  }
}

function checkPaloAltoGlobalProtect0257(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/var/log",
    "/opt",
    "/srv",
    "/etc",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const size = fileSizeBytes(filePath);
    if (size <= 0 || size > 2 * 1024 * 1024) continue;
    const text = readText(filePath);
    if (!text || !/GlobalProtect|PAN-OS|gateway-connected|gateway connected|source_user_info|endpoint_os_version/i.test(text)) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasSuccessfulGateway = /gateway[-\s]?connected|successful\s+(?:login|connection|gateway)|established\s+VPN/i.test(text);

    const matchedIps = GLOBALPROTECT_0257_IPS.filter((indicator) => text.includes(indicator));
    if (matchedIps.length > 0) {
      const severity = hasSuccessfulGateway ? "warning" : "review";
      addFinding(findings, severity, "paloalto-globalprotect-cve-2026-0257-ip-indicator", "GlobalProtect log metadata references CVE-2026-0257 exploitation IP indicators.", `${relative}: ${matchedIps.slice(0, 4).join(", ")}`, "Search GlobalProtect logs for successful gateway-connected events from these IPs, then follow Palo Alto Networks advisory guidance, patch or mitigate PAN-OS, and start incident response for successful sessions.");
    }

    const matchedClients = GLOBALPROTECT_0257_CLIENT_VALUES.filter((indicator) => text.includes(indicator));
    if (matchedClients.length > 0 && hasSuccessfulGateway) {
      addFinding(findings, "warning", "paloalto-globalprotect-cve-2026-0257-client-indicator", "Successful GlobalProtect gateway event references client values reported with CVE-2026-0257 exploitation.", `${relative}: ${matchedClients.slice(0, 4).join(", ")}`, "Treat these as Unit 42 hunting indicators. Review associated user, source IP, portal/gateway, and session activity before clearing the event.");
    }

    const hasPocOs = /endpoint_os_version\s*[:=]\s*["']?Microsoft Windows 10 Pro 64-bit/i.test(text);
    const hasEmptyDomain = /source_user_info\.domain\s*[:=]\s*(?:["']{2}|empty|null|none|\s*(?:[,}\n]|$))/i.test(text);
    if (hasPocOs && hasEmptyDomain && hasSuccessfulGateway) {
      addFinding(findings, "warning", "paloalto-globalprotect-cve-2026-0257-poc-client-config", "Successful GlobalProtect gateway event matches CVE-2026-0257 PoC client configuration values.", `${relative}: endpoint_os_version + empty source_user_info.domain`, "Investigate the VPN session as potentially unauthorized, validate affected PAN-OS versions and mitigations, and preserve GlobalProtect logs before cleanup.");
    }
  }
}

function checkCryptoClipperUsbWorm(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/Users",
    "/mnt",
    "/media",
    "/Volumes",
    "/opt",
    "/srv",
    "/var/log",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const indicator of CRYPTO_CLIPPER_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "crypto-clipper-usb-worm-indicator", "Microsoft/Ars Crypto Clipper USB worm indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Review USB/removable-drive history, Windows shortcut execution, Tor/SOCKS5 activity on localhost:9050, clipboard/screenshot access, and crypto wallet exposure.");
      }
    }

    if (/\.lnk\b/i.test(text) && /USB|removable|drive/i.test(text) && /Tor|SOCKS5|localhost:9050|clipboard|seed phrase|wallet/i.test(text)) {
      addFinding(findings, "warning", "crypto-clipper-usb-lnk-spread-review", "USB .lnk propagation terms co-occur with Crypto Clipper behavior markers.", relative, "Preserve shortcut files and endpoint telemetry. Check for script interpreters spawning child processes, local Tor proxy use, screenshots, clipboard inspection, and wallet address replacement.");
    }

    if (/powershell/i.test(text) && /screenshot|screen.?capture/i.test(text) && /curl|Invoke-WebRequest|Invoke-RestMethod|Tor|SOCKS5|9050/i.test(text)) {
      addFinding(findings, "warning", "crypto-clipper-screenshot-exfil-review", "PowerShell screen-capture and exfiltration terms match Crypto Clipper triage behavior.", relative, "Correlate with Defender alerts for suspicious JavaScript, Curl exfiltration, and Trojan:Win32/CryptoBandits.A.");
    }
  }
}

function checkPeopleSoftCve202635273(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/u01",
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();

    if (base === PEOPLESOFT_EXTORTION_MARKER) {
      addFinding(findings, "critical", "peoplesoft-shinyhunters-extortion-marker", "PeopleSoft/ShinyHunters extortion marker filename exists.", relative, "Contain the affected PeopleSoft/WebLogic host, preserve evidence, and review Oracle/Mandiant remediation guidance before cleanup.");
    }

    if (PEOPLESOFT_MESH_AGENT_FILES.has(base)) {
      addFinding(findings, "critical", "peoplesoft-meshcentral-masquerade-agent", "MeshCentral agent filename used in the PeopleSoft/ShinyHunters campaign exists.", relative, "Treat as possible remote-management persistence. Isolate the host and preserve the binary for incident response.");
    }

    if (loweredRelative.includes("/psemhub.war/") && loweredRelative.endsWith(".jsp")) {
      addFinding(findings, "critical", "peoplesoft-psemhub-unexpected-jsp", "JSP file exists under PSEMHUB.war.", relative, "Mandiant recommends reviewing PSEMHUB.war for JSP files not shipped with the product. Treat unexpected JSP files as potential web shells.");
    }

    if (loweredRelative.includes("/psemhub.war/envmetadata/transactions/")) {
      addFinding(findings, "warning", "peoplesoft-psemhub-transaction-artifact", "File exists under PSEMHUB.war envmetadata transaction paths.", relative, "Review for CVE-2026-35273 exploitation artifacts and preserve timestamps before cleanup.");
    }

    if (/\/psemhub\.war\/(?:logs|persistantstorage|scratchpad)(?:\/|$)/i.test(relative)) {
      addFinding(findings, "warning", "peoplesoft-psemhub-unexpected-directory", "Unexpected PSEMHUB.war directory path reported in exploitation triage exists.", relative, "Review the directory contents and correlate with PeopleSoft/WebLogic access logs.");
    }

    const text = readText(filePath);
    if (!text) continue;

    if (/PeopleTools[^0-9]{0,40}8\.6[12]\b|PeopleSoft Enterprise PeopleTools[^0-9]{0,80}8\.6[12]\b/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-cve-2026-35273-affected-version", "Text references PeopleSoft PeopleTools 8.61 or 8.62, affected by CVE-2026-35273.", relative, "Apply Oracle's June 10, 2026 Security Alert mitigation or patch guidance and restrict PSEMHUB access.");
    }

    if (/\/PSEMHUB\/hub|\/PSIGW\/HttpListeningConnector/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-psemhub-route-review", "File references PeopleSoft PSEMHUB or PSIGW routes used in CVE-2026-35273 triage.", relative, "Review whether these routes are externally reachable or appear in PIA WebLogic access logs from untrusted IPs.");
    }

    for (const indicator of PEOPLESOFT_CAMPAIGN_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "peoplesoft-shinyhunters-network-indicator", "PeopleSoft/ShinyHunters campaign network indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with outbound firewall, NetFlow, WebLogic, and MeshCentral activity. Preserve evidence before rotating credentials from a clean posture.");
      }
    }

    if (/meshctrl\.js\s+RunCommand|README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED\.TXT|_fanout\.sh|psappsrv\.cfg|\/etc\/hosts.*csprd/i.test(text)) {
      addFinding(findings, "warning", "peoplesoft-shinyhunters-operator-artifact", "Text contains PeopleSoft/ShinyHunters operator or reconnaissance artifacts.", relative, "Review shell history, WebLogic logs, process scheduler paths, and lateral movement evidence.");
    }
  }
}

function checkRoundcubeCve202549113(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/usr/share",
    "/usr/local",
    "/var/www",
    "/var/lib",
    "/opt",
    "/srv",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findRoundcubeFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();

    if (hasRoundcube49113PocShape(text, loweredRelative)) {
      addFinding(findings, "warning", "roundcube-cve-2025-49113-poc-artifact", "Roundcube CVE-2025-49113 PoC or exploit-runner artifact appears on disk.", relative, "Keep exploit tooling out of production hosts. Preserve context if unexpected, then remove from a trusted administrative posture.");
    }

    if (!hasRoundcubeInstallSignal(text, loweredRelative)) continue;

    for (const version of roundcubeVersionsInText(text)) {
      if (isRoundcube49113Vulnerable(version)) {
        addFinding(findings, "critical", "roundcube-cve-2025-49113-vulnerable-version", "Roundcube version is affected by CVE-2025-49113 post-auth RCE.", `${relative}: Roundcube ${version}`, `Upgrade Roundcube to ${ROUNDCUBE_16_FIXED} on 1.6.x or ${ROUNDCUBE_15_FIXED} on 1.5.x, or follow distro/control-panel vendor backport guidance. Review authenticated webmail access logs if exposure is suspected.`);
      }
    }

    if (/program\/actions\/settings\/upload\.php|_from\b|session_decode|rcube_session/i.test(text) && loweredRelative.includes("roundcube")) {
      addFinding(findings, "review", "roundcube-cve-2025-49113-code-path-review", "Roundcube upload/session code-path terms appear in scanned files.", relative, "Correlate with installed Roundcube version and vendor package state; the vulnerable range is before 1.5.10 and 1.6.x before 1.6.11.");
    }
  }
}

function checkJoomlaJceCve202648907(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/usr/share",
    "/usr/local",
    "/var/www",
    "/var/lib",
    "/opt",
    "/srv",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findJoomlaJceFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();
    const haystack = `${loweredRelative}\n${text}`;

    if (hasJoomlaJce48907PocOrKevShape(text, loweredRelative)) {
      addFinding(findings, "warning", "joomla-jce-cve-2026-48907-poc-or-kev-reference", "Joomla JCE CVE-2026-48907 exploit/KEV reference appears in scanned files.", relative, "Keep exploit tooling and copied incident notes out of production web roots. Follow CISA KEV and JCE guidance for patching and compromise review.");
    }

    if (!hasJoomlaJceInstallSignal(text, loweredRelative)) continue;

    for (const version of joomlaJceVersionsInText(text, loweredRelative)) {
      if (compareDottedVersion(version, JOOMLA_JCE_FIXED) < 0) {
        addFinding(findings, "critical", "joomla-jce-cve-2026-48907-vulnerable-version", "Joomla Content Editor version is affected by CVE-2026-48907.", `${relative}: JCE ${version}`, `Update JCE Pro/JCE to ${JOOMLA_JCE_FIXED} or later. If exploitation may have occurred, preserve rogue profile evidence, review uploaded PHP artifacts, rotate site/database/hosting credentials from a clean posture, and run server-side malware scanning.`);
      }
    }

    if (/new editor profiles?|rogue profiles?|upload and execution of PHP code|profiles?[^.\n]{0,120}unauthenticated|com_jce[^.\n]{0,160}upload/i.test(haystack)) {
      addFinding(findings, "warning", "joomla-jce-cve-2026-48907-profile-upload-review", "Joomla JCE profile/upload terms match CVE-2026-48907 triage language.", relative, "Review JCE editor profiles, Joomla administrator logs, uploaded PHP files, and web-server logs before clearing this host.");
    }
  }
}

function checkSplunkEnterpriseCve202620253(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt/splunk",
    "/opt",
    "/etc",
    "/var/log",
    "/var/lib",
    "/usr/local",
    "/srv",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const splunkSignal = hasSplunkInstallSignal(text, relative.toLowerCase());

    if (/CVE-2026-20253|BOD 26-04|Known Exploited Vulnerabilities|CISA KEV/i.test(text) && /Splunk|PostgreSQL sidecar|Sidecar Service/i.test(text)) {
      addFinding(findings, "warning", "splunk-cve-2026-20253-kev-reference", "Splunk Enterprise CVE-2026-20253 CISA KEV reference appears in scanned files.", relative, "Prioritize exposure assessment and vendor mitigation. If Splunk Enterprise is reachable from untrusted networks, treat as urgent active-exploitation posture.");
    }

    if (/\/v1\/postgres\/recovery\/(?:backup|restore)\b|PostgreSQL Sidecar Service|PostgreSQL sidecar/i.test(text)) {
      addFinding(findings, "critical", "splunk-cve-2026-20253-postgres-sidecar-endpoint", "Splunk PostgreSQL sidecar recovery endpoint or service reference appears in scanned files.", relative, "Review Splunk web exposure, access logs, and PostgreSQL sidecar access immediately. Apply Splunk mitigation or update guidance; if patching is not possible, remove exposure until secured.");
    }

    if (splunkSignal) {
      for (const version of splunkEnterpriseVersionsInText(text)) {
        if (compareDottedVersion(version, SPLUNK_20253_REVIEW_MIN) >= 0) {
          addFinding(findings, "review", "splunk-cve-2026-20253-enterprise-10-review", "Splunk Enterprise 10.x or later reference appears in scanned files.", `${relative}: Splunk Enterprise ${version}`, "Verify whether this deployment includes the PostgreSQL sidecar service and whether Splunk/CISA mitigation for CVE-2026-20253 has been applied.");
        }
      }
    }

    if (splunkSignal && /pg_restore|pg_dump|\.pgpass|backupFile|large object export|arbitrary file (?:write|creation|truncation)|database parameter|restore feature/i.test(text)) {
      addFinding(findings, "warning", "splunk-cve-2026-20253-file-write-chain-review", "Splunk PostgreSQL sidecar file-write/RCE-chain triage terms appear in scanned files.", relative, "Review file-integrity drift in Splunk-owned paths, unusual recovery endpoint access, PostgreSQL sidecar logs, and recent file creation/truncation events before clearing the host.");
    }
  }
}

function checkRedcapExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/var/www",
    "/srv",
    "/opt",
    "/usr/local",
    "/etc",
    "/var/log",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();
    const redcapSignal = hasRedcapSignal(text, loweredRelative);

    if (!redcapSignal) continue;

    for (const version of redcapVersionsInText(text, loweredRelative)) {
      if (compareDottedVersion(version, REDCAP_REVIEW_LATEST) < 0) {
        addFinding(findings, "review", "redcap-outdated-version-review", "REDCap version appears older than the latest version cited by Censys/SecurityWeek on 2026-06-16.", `${relative}: REDCap ${version}`, `Inventory internet exposure, update toward ${REDCAP_REVIEW_LATEST} or current vendor release, and review whether legacy REDCap versions are running side-by-side.`);
      }
    }

    for (const indicator of REDCAP_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "redcap-exposure-indicator", "REDCap deployment or campaign triage term appears in scanned files.", `${relative}: ${indicator}`, "Confirm REDCap internet exposure, patch level, legacy-version availability, authentication posture, and web/database separation.");
      }
    }

    if (/UNC6508|InfiniteRed|credential harvesting|legacy REDCap|China-linked|cyberespionage/i.test(text)) {
      addFinding(findings, "warning", "redcap-unc6508-triage-note", "REDCap UNC6508 / InfiniteRed triage language appears in scanned files.", relative, "Review REDCap access logs, administrator accounts, suspicious modules/files, credential harvesting evidence, and internal network access from the REDCap host.");
    }
  }
}

function checkFortinetCredentialExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/etc",
    "/var/log",
    "/var/lib",
    "/opt",
    "/srv",
    "/usr/local",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const loweredRelative = relative.toLowerCase();
    const fortinetSignal = hasFortinetSignal(text, loweredRelative);

    if (!fortinetSignal) continue;

    for (const indicator of FORTINET_CREDENTIAL_EXPOSURE_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "fortinet-credential-exposure-indicator", "Fortinet/FortiGate credential-exposure or hardening indicator appears in scanned files.", `${relative}: ${indicator}`, "Inventory Fortinet edge devices, confirm firmware and management exposure, rotate Fortinet/VPN/LDAP/AD-linked credentials from a clean posture, enforce MFA, and review authentication/config-export logs.");
      }
    }

    if (/FortiBleed|credential dump|plaintext passwords?|bruteforc(?:e|ing)|credential attempts|VPN authentication hashes|cracked.*Active Directory|configuration export|firewall configuration data/i.test(text)) {
      addFinding(findings, "warning", "fortinet-fortigate-credential-dump-triage", "Fortinet/FortiGate credential dump or brute-force triage language appears in scanned files.", relative, "Treat exposed or reused Fortinet credentials as urgent edge-device posture. Check successful VPN/admin logins, unexpected admin accounts, config exports, LDAP/AD bindings, and downstream lateral movement before clearing.");
    }

    if (/admin-forticloud-sso-login|FortiCloud SSO|FortiCloud login/i.test(text)) {
      addFinding(findings, "review", "fortinet-forticloud-sso-review", "FortiCloud SSO/login configuration or mitigation language appears in scanned files.", relative, "Verify current Fortinet vendor guidance for FortiCloud SSO, restrict management-plane access, and confirm whether SSO-related mitigations or updates apply to this deployment.");
    }
  }
}

function checkClickFixKb4Phishing(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/mnt",
    "/media",
    "/ProgramData",
    "/Users",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const ext = path.extname(base).toLowerCase();
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const size = fileSizeBytes(filePath);

    if (/^Review Past Due Doc\. ?zip$/i.test(base)) {
      addFinding(findings, "warning", "clickfix-kb4-onedrive-zip-lure", "KnowBe4 ClickFix OneDrive lure ZIP filename appears in scanned host tree.", relative, "Preserve the ZIP and any extracted .lnk shortcut. Review shell/run dialog telemetry, clipboard access, DNS TXT lookups, and PowerShell child processes.");
    }

    if ([".zip", ".msi", ".iso", ".lnk", ".js", ".vbs", ".exe"].includes(ext) && size > 0 && size <= 500 * 1024 * 1024) {
      const digest = sha256File(filePath);
      const label = CLICKFIX_KB4_KNOWN_HASHES.get(digest);
      if (label) {
        addFinding(findings, "critical", "clickfix-kb4-known-sha256", "Known KnowBe4 ClickFix campaign SHA-256 observed.", `${relative}: ${label}; sha256=${digest}`, "Do not execute the artifact. Preserve it for incident response, isolate affected endpoints, and rotate credentials if the stager or payload may have run.");
      }
    }

    const text = size <= 1024 * 1024 ? readText(filePath) : "";
    if (!text) continue;

    for (const indicator of CLICKFIX_KB4_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "clickfix-kb4-network-indicator", "KnowBe4 ClickFix phishing infrastructure indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with DNS, proxy, browser, PowerShell, and EDR telemetry. Preserve the original lure and review credential/RMM exposure.");
      }
    }

    for (const indicator of CLICKFIX_KB4_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "clickfix-kb4-text-indicator", "KnowBe4 ClickFix lure, stager, or payload indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Review for ZIP/.lnk execution, victim-assisted Win+R paste behavior, DNS TXT staging, MSI/RMM drops, spyware, and password-stealer execution.");
      }
    }

    if (/\.lnk[\s\S]{0,240}(?:Win\s*\+\s*R|clipboard|PowerShell|DNS TXT|OneDrive)|(?:Win\s*\+\s*R|clipboard|PowerShell|DNS TXT|OneDrive)[\s\S]{0,240}\.lnk/i.test(text)) {
      addFinding(findings, "warning", "clickfix-kb4-lnk-clipboard-stager", "KnowBe4 ClickFix .lnk plus clipboard/PowerShell/DNS-TXT staging behavior appears in scanned metadata.", relative, "Preserve the shortcut and command history. Check clipboard access, PowerShell execution policy bypasses, DNS TXT responses, and spawned MSI/RMM or spyware payloads.");
    }
  }
}

function checkFfmpegPixelSmashExposure(findings, targetRoot, homePath) {
  const packageStatus = readText(mapLinuxPath(targetRoot, "/var/lib/dpkg/status"));
  const ffmpegPackages = ffmpegPackagesFromDpkgStatus(packageStatus);
  for (const pkg of ffmpegPackages) {
    addFinding(findings, "review", "ffmpeg-pixelsmash-package-review", "FFmpeg/libavcodec package appears installed on a host relevant to PixelSmash CVE-2026-8461.", `${pkg.name} ${pkg.version}`, "Confirm FFmpeg 8.1.2 or a vendor-fixed backport. If MagicYUV is not needed, consider disabling the decoder and restrict automated processing of untrusted AVI/MKV/MOV media.");

    const upstreamVersion = normalizePackageVersion(pkg.version);
    if (upstreamVersion && compareDottedVersion(normalizeDottedVersion(upstreamVersion), FFMPEG_PIXELSMASH_FIXED) < 0) {
      addFinding(findings, "warning", "ffmpeg-pixelsmash-upstream-version-review", "FFmpeg/libavcodec package version appears older than the upstream PixelSmash fixed release.", `${pkg.name} ${pkg.version}`, "Do not rely on upstream-looking versions alone for distro packages. Verify CVE-2026-8461 backport status, MagicYUV decoder exposure, and media-ingestion workflows.");
    }
  }

  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    "/etc",
    "/opt",
    "/srv",
    "/var/www",
    "/var/log",
    "/mnt",
    "/media",
    homeRelative,
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const indicator of FFMPEG_PIXELSMASH_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "ffmpeg-pixelsmash-text-indicator", "PixelSmash / FFmpeg MagicYUV exposure term appears in scanned host metadata.", `${relative}: ${indicator}`, "Review FFmpeg/libavcodec versions, whether the MagicYUV decoder is enabled, and whether untrusted AVI/MKV/MOV files are processed automatically.");
      }
    }

    if (/(?:jellyfin|emby|nextcloud|immich|photoprism|obs|ffmpegthumbnailer|thumbnailer)[\s\S]{0,300}(?:ffmpeg|ffprobe|libavcodec|magicyuv|MagicYUV|AVI|MKV|MOV)|(?:ffmpeg|ffprobe|libavcodec|magicyuv|MagicYUV|AVI|MKV|MOV)[\s\S]{0,300}(?:jellyfin|emby|nextcloud|immich|photoprism|obs|ffmpegthumbnailer|thumbnailer)/i.test(text)) {
      addFinding(findings, "warning", "ffmpeg-pixelsmash-media-ingestion-review", "Media ingestion or thumbnailing terms co-occur with FFmpeg/MagicYUV PixelSmash exposure terms.", relative, "Patch FFmpeg or bundled media-app FFmpeg builds, disable MagicYUV if unnecessary, and avoid auto-scanning untrusted media libraries until fixed.");
    }

    if (/--disable-decoder=magicyuv|disable(?:d)?\s+MagicYUV|MagicYUV\s+decoder\s+disabled/i.test(text)) {
      addFinding(findings, "info", "ffmpeg-pixelsmash-magicyuv-disabled-note", "Scanned metadata references disabling the MagicYUV decoder as PixelSmash mitigation.", relative, "Confirm the active FFmpeg build really excludes the magicyuv decoder with `ffmpeg -decoders`, then continue tracking vendor packages.");
    }
  }
}

function checkLibssh2Cve202655200Exposure(findings, targetRoot, homePath) {
  const packageStatus = readText(mapLinuxPath(targetRoot, "/var/lib/dpkg/status"));
  const libssh2Packages = libssh2PackagesFromDpkgStatus(packageStatus);
  for (const pkg of libssh2Packages) {
    addFinding(findings, "review", "libssh2-cve-2026-55200-package-review", "libssh2 package appears installed on a host relevant to CVE-2026-55200 client-side SSH/SCP/SFTP exposure.", `${pkg.name} ${pkg.version}`, `Confirm a vendor-fixed build that includes libssh2 commit ${LIBSSH2_CVE202655200_FIXED_COMMIT} or later.`);

    const upstreamVersion = normalizePackageVersion(pkg.version);
    if (upstreamVersion && compareDottedVersion(normalizeDottedVersion(upstreamVersion), LIBSSH2_CVE202655200_AFFECTED_MAX) <= 0) {
      addFinding(findings, "warning", "libssh2-cve-2026-55200-affected-version", "Installed libssh2 package version is in the reported affected range through 1.11.1.", `${pkg.name} ${pkg.version}`, "Patch through the distribution or rebuild with the upstream packet_length boundary checks. Prioritize clients that connect to untrusted SSH/SCP/SFTP servers or cross hostile networks.");
    }
  }

  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    "/etc",
    "/opt",
    "/srv",
    "/usr/local",
    "/var/log",
    "/mnt",
    "/media",
    homeRelative,
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const size = fileSizeBytes(filePath);
    if (size <= 0 || size > 1024 * 1024) continue;
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (LIBSSH2_CVE202655200_POC_FILES.has(base)
      || relative.includes("/libssh2-cve-2026-55200-poc/")) {
      addFinding(findings, "review", "libssh2-cve-2026-55200-poc-artifact", "libssh2 CVE-2026-55200 PoC artifact appears in scanned host metadata.", relative, "Treat as research code until provenance and authorization are verified. Do not execute PoC scaffolds on workstations or shared runners during routine triage.");
    }

    const versions = packageVersionsInText(text, "libssh2");
    for (const version of versions) {
      if (compareDottedVersion(normalizeDottedVersion(version), LIBSSH2_CVE202655200_AFFECTED_MAX) <= 0) {
        addFinding(findings, "warning", "libssh2-cve-2026-55200-affected-version", "Scanned metadata references libssh2 in the CVE-2026-55200 affected range through 1.11.1.", `${relative}: libssh2 ${version}`, "Inventory statically linked clients and bundled builds, not only system packages. Verify whether the packet_length boundary-check commit is present.");
      }
    }

    for (const indicator of LIBSSH2_CVE202655200_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "libssh2-cve-2026-55200-text-indicator", "libssh2 CVE-2026-55200 / CVE-2026-55199 advisory term appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with package state, bundled libraries, static builds, and clients that connect to SSH, SCP, or SFTP servers.");
      }
    }

    for (const indicator of LIBSSH2_CVE202655200_POC_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "libssh2-cve-2026-55200-poc-indicator", "libssh2 CVE-2026-55200 PoC/exploitarium marker appears in scanned host metadata.", `${relative}: ${indicator}`, "Review whether this is authorized research material. Keep PoC files out of ordinary build, CI, and developer credential contexts.");
      }
    }

    if (/libssh2/i.test(text) && /curl|git|rsync|backup|artifact|mirror|fetch/i.test(text)) {
      addFinding(findings, "review", "libssh2-cve-2026-55200-client-linkage-review", "libssh2 appears near client workflow terms.", relative, "Inventory linked binaries and bundled libraries used by outbound transfer tooling. A malicious or MITM-positioned server can target vulnerable clients.");
    }
  }
}

function checkShapedPluginSupplyChainCompromise(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    "/var/www",
    "/srv",
    "/opt",
    "/mnt",
    "/media",
    homeRelative,
  ].filter(Boolean);

  for (const fakePath of SHAPEDPLUGIN_FAKE_PLUGIN_PATHS) {
    if (exists(mapLinuxPath(targetRoot, fakePath))) {
      addFinding(findings, "critical", "shapedplugin-fake-plugin-path", "Wordfence-reported ShapedPlugin fake WooCommerce plugin path exists.", fakePath, "Treat the WordPress site as compromised. Preserve files, rotate WordPress/database/mail/API credentials, revoke 2FA seeds, and review administrator accounts.");
    }
  }

  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const size = fileSizeBytes(filePath);

    for (const fakePath of SHAPEDPLUGIN_FAKE_PLUGIN_PATHS) {
      if (relative.includes(`${fakePath}/`) || relative.endsWith(fakePath)) {
        addFinding(findings, "critical", "shapedplugin-fake-plugin-path", "Wordfence-reported ShapedPlugin fake WooCommerce plugin path exists.", relative, "Treat the WordPress site as compromised. Preserve files, rotate WordPress/database/mail/API credentials, revoke 2FA seeds, and review administrator accounts.");
      }
    }

    if (base === "LicenseLoader.php" || base === "install-persistent.php") {
      addFinding(findings, "critical", "shapedplugin-loader-or-persistence-file", "ShapedPlugin supply-chain loader or persistence filename exists in scanned WordPress tree.", relative, "Preserve the file, compare against known ShapedPlugin Pro packages, and treat credentials and 2FA seeds as exposed if execution occurred.");
    }

    if (size > 0 && size <= 10 * 1024 * 1024 && ["LicenseLoader.php", "install-persistent.php", "class-wc-subscription-trace-dispatch.php", "class-wc-subscription-diagnostics.php", "class-wc-subscription-scheduler.php"].includes(base)) {
      const digest = sha256File(filePath);
      const label = SHAPEDPLUGIN_KNOWN_HASHES.get(digest);
      if (label) {
        addFinding(findings, "critical", "shapedplugin-known-sha256", "Known ShapedPlugin supply-chain malware SHA-256 observed.", `${relative}: ${label}; sha256=${digest}`, "Preserve the artifact and immediately begin WordPress incident response, including credential and 2FA-secret rotation from a clean machine.");
      }
    }

    const text = size <= 1024 * 1024 ? readText(filePath) : "";
    if (!text) continue;

    const versions = shapedPluginVersionsInText(text);
    for (const item of versions) {
      if (isShapedPluginAffectedVersion(item.slug, item.version)) {
        addFinding(findings, "critical", "shapedplugin-affected-pro-version", "ShapedPlugin Pro plugin version matches the reported supply-chain compromise range.", `${relative}: ${item.slug} ${item.version}`, "Treat the site as potentially compromised if this Pro build was installed through the licensed ShapedPlugin update channel. Scan with Wordfence/CLI and rotate WordPress, database, mail, and 2FA secrets.");
      }
    }

    for (const indicator of SHAPEDPLUGIN_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "shapedplugin-network-indicator", "ShapedPlugin supply-chain C2 or exfiltration indicator appears in scanned WordPress metadata.", `${relative}: ${indicator}`, "Correlate web logs, DNS/proxy telemetry, WordPress admin activity, and mail plugin credentials before cleanup.");
      }
    }

    for (const indicator of SHAPEDPLUGIN_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "shapedplugin-text-indicator", "ShapedPlugin supply-chain compromise indicator appears in scanned WordPress metadata.", `${relative}: ${indicator}`, "Review for fake WooCommerce plugin directories, REST backdoor endpoint, credential/2FA theft hooks, and unauthorized admin accounts.");
      }
    }

    if (/wp_authenticate|wp_login|session cookies?|TOTP|2FA|two[- ]factor|wp_2fa_totp_key|wfls_2fa_secrets|rsssl_totp_secret|_two_factor_totp_key/i.test(text)
      && /generate\.2faplugin\.org|class-wc-subscription-trace-dispatch|woocommerce-subscription|woocommerce-notification/i.test(text)) {
      addFinding(findings, "critical", "shapedplugin-credential-2fa-stealer", "ShapedPlugin-style WordPress credential and 2FA secret theft markers co-occur.", relative, "Assume WordPress admin passwords, sessions, TOTP seeds, database credentials, mail plugin credentials, and WooCommerce data may be exposed.");
    }

    if (/\/wp-json\/wc\/v3\/settings\/apply|arbitrary file writes?|base64-encoded payload|Tiny File Manager|Adminer 5\.2\.1|shell_exec|passthru|eval/i.test(text)
      && (/install-persistent\.php|woocommerce-subscription|woocommerce-notification|ShapedPlugin/i.test(text) || base === "install-persistent.php" || SHAPEDPLUGIN_FAKE_PLUGIN_PATHS.some((fakePath) => relative.includes(`${fakePath}/`)))) {
      addFinding(findings, "critical", "shapedplugin-rest-webshell-backdoor", "ShapedPlugin-style REST/webshell persistence markers co-occur.", relative, "Preserve the WordPress tree and logs, remove persistence only after evidence capture, and rebuild/restore from a trusted baseline where practical.");
    }
  }
}

function checkSquidbleedFtpProxyExposure(findings, targetRoot, homePath) {
  const packageStatus = readText(mapLinuxPath(targetRoot, "/var/lib/dpkg/status"));
  const squidDpkg = squidPackagesFromDpkgStatus(packageStatus);
  for (const pkg of squidDpkg) {
    addFinding(findings, "review", "squidbleed-squid-package-review", "Squid package appears installed on a host affected by the Squidbleed CVE-2026-47729 FTP-parser review lane.", `${pkg.name} ${pkg.version}`, "Confirm the FtpGateway.cc fix or distro backport. Disable FTP proxying if not required, restrict outbound TCP/21 from the proxy, and avoid forwarding cleartext HTTP credentials through shared Squid instances.");
  }

  const configPaths = new Set(SQUIDBLEED_CONFIG_PATHS);
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    "/etc",
    "/usr/local/squid/etc",
    "/opt",
    "/srv",
    homeRelative,
  ].filter(Boolean);
  for (const root of roots) {
    for (const filePath of findWatchFiles(mapLinuxPath(targetRoot, root), 15000)) {
      const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
      if (/\/squid(?:3)?\/squid\.conf$/i.test(relative) || /\/squid\.conf$/i.test(relative)) {
        configPaths.add(relative);
      }
    }
  }

  for (const configPath of configPaths) {
    const resolved = mapLinuxPath(targetRoot, configPath);
    if (!exists(resolved)) continue;
    const text = readText(resolved);
    if (!text) continue;
    const activeText = stripHashComments(text);
    addFinding(findings, "review", "squidbleed-squid-config-present", "Squid proxy configuration is present; review FTP proxy exposure for Squidbleed CVE-2026-47729.", configPath, "If FTP proxying is not explicitly required, remove TCP/21 from Safe_ports and block proxy egress to attacker-controlled FTP servers.");

    if (squidConfigAllowsFtpSafePort(activeText)) {
      addFinding(findings, "warning", "squidbleed-ftp-safe-port-exposure", "Squid configuration allows FTP port 21 through Safe_ports, matching a Squidbleed CVE-2026-47729 exposure precondition.", configPath, "Remove or comment the Safe_ports port 21 rule unless FTP proxying is required, reload Squid, and confirm the FtpGateway.cc fix or vendor backport status.");
    }

    if (/ftp:\/\/|ftp_port|ftp_passive|ftp_epsv|ftp_user/i.test(activeText)) {
      addFinding(findings, "warning", "squidbleed-ftp-proxy-feature-review", "Squid FTP proxy configuration or FTP URL references appear in active configuration.", configPath, "Review whether FTP proxy support is still needed. Modern browsers dropped FTP support, so legitimate usage is usually rare.");
    }
  }
}

function checkNginxCritical2026Exposure(findings, targetRoot, homePath) {
  const packageStatus = readText(mapLinuxPath(targetRoot, "/var/lib/dpkg/status"));
  const nginxPackages = nginxPackagesFromDpkgStatus(packageStatus);
  for (const pkg of nginxPackages) {
    const upstreamVersion = normalizePackageVersion(pkg.version);
    if (isNginx42530Affected(upstreamVersion)) {
      addFinding(findings, "critical", "nginx-cve-2026-42530-affected-version", "NGINX Open Source version is in the CVE-2026-42530 HTTP/3/QPACK affected range.", `${pkg.name} ${pkg.version}`, "Upgrade NGINX Open Source to 1.31.2 or later, or use a vendor-fixed backport. Disable HTTP/3 until fixed.");
    }
    if (isNginx42055Affected(upstreamVersion)) {
      addFinding(findings, "critical", "nginx-cve-2026-42055-affected-version", "NGINX Open Source version is in the CVE-2026-42055 HTTP/2 proxy/gRPC affected range.", `${pkg.name} ${pkg.version}`, "Upgrade NGINX Open Source to 1.31.2, 1.30.3, or a vendor-fixed backport. Review HTTP/2 proxy and gRPC configuration before returning exposed services to normal operation.");
    }
    if (/nginx-plus/i.test(pkg.name)) {
      addFinding(findings, "review", "nginx-plus-2026-critical-review", "NGINX Plus package is present; F5 listed multiple NGINX Plus releases in the CVE-2026-42055 advisory.", `${pkg.name} ${pkg.version}`, "Confirm F5 fixed release status for this exact NGINX Plus train, including R36 P6 or 37.0.2.1 where applicable.");
    }
  }

  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    ...NGINX_CONFIG_ROOTS,
    homeRelative,
  ].filter(Boolean);
  const configFiles = [];
  for (const root of roots) {
    configFiles.push(...findNginxConfigFiles(mapLinuxPath(targetRoot, root), 25000 - configFiles.length));
    if (configFiles.length >= 25000) break;
  }

  for (const filePath of configFiles) {
    const text = readText(filePath);
    if (!text) continue;
    const activeText = stripHashComments(text);
    if (!activeText.trim()) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (/\blisten\b[^\n;]*(?:quic|http3)|\bhttp3\s+on\b|\bssl_early_data\b/i.test(activeText)) {
      addFinding(findings, "warning", "nginx-cve-2026-42530-http3-quic-config", "NGINX configuration enables HTTP/3/QUIC exposure relevant to CVE-2026-42530.", relative, "Disable HTTP/3/QUIC until the deployed NGINX build is confirmed fixed for CVE-2026-42530.");
    }

    const hasHttp2Proxy = /\bproxy_http_version\s+2(?:\.0)?\s*;/i.test(activeText);
    const hasGrpcPass = /\bgrpc_pass\s+/i.test(activeText);
    const ignoresInvalidHeaders = /\bignore_invalid_headers\s+off\s*;/i.test(activeText);
    const oversizedHeaderBuffer = nginxHasLargeClientHeaderBuffersOver2m(activeText);

    if ((hasHttp2Proxy || hasGrpcPass) && ignoresInvalidHeaders && oversizedHeaderBuffer) {
      addFinding(findings, "critical", "nginx-cve-2026-42055-config-chain", "NGINX configuration matches the CVE-2026-42055 HTTP/2 proxy/gRPC exploitability preconditions.", relative, "Remove ignore_invalid_headers off, reduce large_client_header_buffers size below 2 MB, and patch NGINX before exposing this configuration.");
    } else if ((hasHttp2Proxy || hasGrpcPass) && ignoresInvalidHeaders) {
      addFinding(findings, "warning", "nginx-cve-2026-42055-http2-invalid-headers-review", "NGINX HTTP/2 proxy/gRPC configuration disables invalid-header rejection.", relative, "Review large_client_header_buffers sizing and patch status for CVE-2026-42055.");
    }
  }
}

function checkLiteLlmGatewayExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasLiteLlm = hasAnyTerm(text, LITELLM_CONFIG_TERMS);
    const liteLlmVersions = packageVersionsInText(text, "litellm");
    const starletteVersions = packageVersionsInText(text, "starlette");

    for (const version of liteLlmVersions) {
      if (isVersionInRange(version, LITELLM_AFFECTED_MIN, LITELLM_FIXED)) {
        addFinding(findings, "critical", "litellm-cve-2026-42271-vulnerable-version", "LiteLLM dependency is in the CVE-2026-42271 affected range.", `${relative}: litellm ${version}`, `Upgrade LiteLLM to ${LITELLM_FIXED} or newer, restrict admin/MCP routes, and rotate proxy/provider credentials if exposure is suspected.`);
      }
    }

    if (hasLiteLlm) {
      for (const version of starletteVersions) {
        if (compareDottedVersion(version, STARLETTE_FIXED) < 0) {
          addFinding(findings, "warning", "litellm-starlette-host-header-chain", "LiteLLM appears with a Starlette version vulnerable to the Host-header authentication-bypass chain.", `${relative}: starlette ${version}`, `Upgrade Starlette to ${STARLETTE_FIXED} or newer, then review LiteLLM authentication and reverse-proxy Host-header handling.`);
        }
      }
    }

    if (hasLiteLlm && exposesAllInterfaces(text)) {
      addFinding(findings, "warning", "litellm-public-bind", "LiteLLM-related config appears to bind a service to all interfaces.", relative, "Bind the LiteLLM proxy to localhost/private interfaces unless deliberate, and place admin/MCP routes behind trusted network controls.");
    }

    for (const route of LITELLM_MCP_TEST_ROUTES) {
      if (text.includes(route)) {
        addFinding(findings, "warning", "litellm-mcp-test-route-reference", "LiteLLM MCP test endpoint route appears in scanned config or source.", `${relative}: ${route}`, "If this route is reachable, block it at the reverse proxy/API gateway or require admin-only access.");
      }
    }

    if (hasLiteLlm && /Host\s*[:=]|host_header|trusted_hosts|allowed_hosts/i.test(text)) {
      addFinding(findings, "review", "litellm-host-header-review", "LiteLLM-related config mentions Host-header or trusted-host handling.", relative, "Review for Starlette Host-header bypass exposure and require strict trusted-host validation.");
    }

    if (hasLiteLlm) {
      const keyTerms = PROVIDER_KEY_ENV_TERMS.filter((term) => text.includes(term));
      if (keyTerms.length > 0) {
        addFinding(findings, "review", "litellm-provider-key-blast-radius", "LiteLLM-related config references provider credential environment names.", `${relative}: ${keyTerms.join(", ")}`, "Do not print secret values. If the proxy was exposed, rotate provider/proxy keys from a clean posture.");
      }
    }
  }
}

function checkDifyTapExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasDify = hasAnyTerm(text, DIFY_DEPLOYMENT_TERMS) || /\/console\/api\/files\/\{?file_id\}?\/preview|\/chat-messages|Plugin Daemon/i.test(text);
    if (!hasDify) continue;

    for (const version of difyVersionsInText(text)) {
      if (compareDottedVersion(normalizeDottedVersion(version), DIFY_FIXED) < 0) {
        addFinding(findings, "critical", "difytap-vulnerable-version", "Dify version appears older than the DifyTap fixed release for most reported flaws.", `${relative}: Dify ${version}`, `Upgrade Dify to ${DIFY_FIXED} or newer where available, then separately track CVE-2026-41948 because reporting said that path-traversal fix was still pending after 1.14.2.`);
      }
    }

    if (/plugin[-_\s]?daemon|PLUGIN_DAEMON|\/plugin(?:[-_]?daemon)?\/|internal REST API|PluginDaemon/i.test(text)) {
      addFinding(findings, "warning", "difytap-plugin-daemon-exposure-review", "Dify Plugin Daemon or internal plugin API terms appear in scanned configuration/source.", relative, "Ensure the Plugin Daemon is not reachable from untrusted clients and track CVE-2026-41948 path-traversal fix status.");
    }

    if (/\/console\/api\/files\/(?:\{file_id\}|<file_id>|[A-Za-z0-9_-]+)\/preview|file_id.*preview|preview.*file_id/i.test(text)) {
      addFinding(findings, "warning", "difytap-file-preview-endpoint-review", "Dify file-preview endpoint terms match the DifyTap cross-tenant document preview lane.", relative, "Review tenant/workspace authorization checks, file UUID logging, and whether uploaded document previews could expose cross-tenant content.");
    }

    if (/chat-messages|files\s*:\s*\[|file\s+uuid|file_uuid|upload_file_id/i.test(text) && /dify|Dify|langgenius/i.test(text)) {
      addFinding(findings, "warning", "difytap-chat-file-uuid-review", "Dify chat-message file UUID terms match the DifyTap same-tenant file-read lane.", relative, "Review chat-message file attachment authorization and rotate secrets if private uploaded documents may have been exposed.");
    }

    if (/trace configuration|trace provider|tracing provider|LLM trace|Langfuse|LangSmith|Arize|OpenTelemetry/i.test(text) && /dify|Dify|app_id|tenant|workspace/i.test(text)) {
      addFinding(findings, "critical", "difytap-trace-exfiltration-review", "Dify tracing configuration terms match the DifyTap cross-tenant chat exfiltration lane.", relative, "Audit trace-provider settings for public apps, disable unauthorized tracing, and review whether prompts/responses were forwarded to attacker-controlled providers.");
    }

    if (/PDFium|CVE-2024-5846|pdfium|use-after-free/i.test(text) && /dify|Dify|document|upload|parser/i.test(text)) {
      addFinding(findings, "warning", "difytap-pdfium-parser-review", "Dify document parsing stack terms reference PDFium/CVE-2024-5846 risk.", relative, "Patch the document parsing image/library and treat untrusted PDF uploads as potential parser attack surface.");
    }
  }
}

function checkOpenClawAgentExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/usr/local/lib/node_modules",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const maybeOpenClaw =
      /\bopenclaw\b/i.test(text) ||
      isOpenClawConfigFileName(path.basename(filePath)) ||
      relative.toLowerCase().includes("/openclaw/") ||
      /\bdmPolicy\b|\ballowFrom\b|agents\.defaults\.sandbox/i.test(text);
    if (!maybeOpenClaw) continue;

    const openClawVersions = packageVersionsInText(text, "openclaw");
    for (const version of openClawVersions) {
      if (compareDottedVersion(version, OPENCLAW_FIXED) < 0) {
        addFinding(findings, "warning", "openclaw-vulnerable-version", "OpenClaw version predates the message-object prompt-boundary fix.", `${relative}: openclaw ${version}`, `Upgrade OpenClaw to ${OPENCLAW_FIXED} or newer before exposing message channels.`);
      }
    }

    const hasOpenDmPolicy = /\bdmPolicy["']?\s*[:=]\s*["']open["']/i.test(text);
    const hasWildcardAllowFrom = /\ballowFrom["']?\s*[:=][\s\S]{0,160}["']\*["']/i.test(text);
    const hasDisabledSandbox = /(?:agents\.defaults\.sandbox\.mode|sandbox[\s\S]{0,80}\bmode)["']?\s*[:=]\s*["'](?:none|off|host|main|disabled)["']/i.test(text);

    if (hasOpenDmPolicy && hasWildcardAllowFrom) {
      addFinding(findings, "warning", "openclaw-open-dm-wildcard", "OpenClaw config appears to allow public inbound DMs with a wildcard allowlist.", relative, "Require pairing or stable sender allowlists before enabling agent actions from messaging channels.");
    }

    if (hasOpenDmPolicy && hasDisabledSandbox) {
      addFinding(findings, "warning", "openclaw-open-dm-unsandboxed", "OpenClaw config appears to combine open inbound DMs with host/main/disabled sandbox mode.", relative, "Route untrusted channels to sandboxed non-main agents and gate outbound mail, credential forwarding, shell, and file actions.");
    }
  }
}

function checkAgentjackingSentryMcpExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasSentry = hasAnyTerm(text, AGENTJACKING_SENTRY_TERMS);
    const hasMcp = hasAnyTerm(text, AGENTJACKING_MCP_TERMS);

    if (hasSentry && hasMcp) {
      addFinding(findings, "review", "agentjacking-sentry-mcp-review", "Sentry appears wired into an MCP/agent context.", relative, "Treat Sentry event content as untrusted tool output. Require human approval before agents execute commands suggested by Sentry issues.");
    }

    if (
      /(?:##\s*Resolution|resolution\s*:)/i.test(text) &&
      /\bnpx\b/i.test(text) &&
      /sentry|Sentry|event|issue|error/i.test(text)
    ) {
      addFinding(findings, "warning", "agentjacking-sentry-resolution-npx", "Sentry-style resolution content attempts npm execution.", relative, "Review for Agentjacking-style indirect prompt injection before giving this content to a coding agent.");
    }

    if (/advisory-tracker\.com|X-Tenet-Security|ResponsibleDisclosure\s*\[SECURITY SCAN\]/i.test(text)) {
      addFinding(findings, "review", "agentjacking-tenet-validation-marker", "Tenet Agentjacking validation marker appears in scanned host metadata.", relative, "Correlate with Sentry events, agent command history, package-manager logs, and developer credential exposure.");
    }
  }
}

function checkAutoJackAgentLocalhostExposure(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const hasAutoGen = /autogenstudio|AutoGen Studio|autogen/i.test(text);
    const hasLocalMcpControlPlane =
      /\/api\/mcp\/ws|StdioServerParams|server_params|localhost:8081|127\.0\.0\.1:8081|Model Context Protocol/i.test(text);

    for (const indicator of AUTOJACK_AGENT_LOCALHOST_TERMS) {
      if (text.includes(indicator)) {
        addFinding(findings, "review", "autojack-agent-localhost-indicator", "AutoJack / AutoGen local MCP control-plane indicator appears in scanned host metadata.", `${relative}: ${indicator}`, "Review whether any browsing or code-execution agent shares a host/profile with AutoGen Studio or other privileged localhost services. Localhost is not a trust boundary for agents that render untrusted content.");
      }
    }

    if (hasAutoGen && hasLocalMcpControlPlane) {
      addFinding(findings, "warning", "autojack-local-mcp-control-plane-review", "AutoGen/AutoGen Studio appears near localhost MCP WebSocket or command-parameter terms.", relative, "Isolate AutoGen Studio and browsing agents into separate users, containers, or VMs; require authentication on all local control-plane routes; allowlist MCP server executables; and avoid running prototypes in the daily-driver account.");
    }

    if (/autogenstudio[^\\n\\r]{0,120}0\.4\.3\.dev[12]|0\.4\.3\.dev[12][^\\n\\r]{0,120}autogenstudio/i.test(text)) {
      addFinding(findings, "warning", "autojack-autogenstudio-prerelease-review", "autogenstudio pre-release version reported with the AutoJack MCP WebSocket issue appears in scanned files.", relative, "Do not run the pre-release build with untrusted browsing agents. Use GitHub main at or after commit b047730 for MCP support, or use a stable PyPI build without the MCP route.");
    }
  }
}

function checkNpmV12Readiness(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    homeRelative,
    "/opt",
    "/srv",
    "/var/www",
    "/etc",
    "/root",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    if (base === "package.json") {
      const npmVersions = npmVersionsInText(text);
      for (const version of npmVersions) {
        if (compareDottedVersion(version, NPM_V12_PREPARE_MIN) < 0) {
          addFinding(findings, "review", "npm-v12-prep-old-npm-pin", "Project pins npm older than the npm v12 migration-warning release.", `${relative}: npm ${version}`, `Use npm ${NPM_V12_PREPARE_MIN} or newer to review install-script and non-registry-source warnings before npm v12.`);
        }
      }
    }

    if (DEPENDENCY_FILE_NAMES.has(base)) {
      if (/"hasInstallScript"\s*:\s*true/i.test(text) && !/"allowScripts"\s*:/i.test(text)) {
        addFinding(findings, "review", "npm-v12-install-script-approval-review", "Dependency metadata records install scripts without visible npm approval metadata.", relative, "Run npm 11.16+ and review npm approve-scripts output before npm v12.");
      }
      if (/"https?:\/\/[^"]+\.(?:tgz|tar\.gz)(?:[?#][^"]*)?"/i.test(text)) {
        addFinding(findings, "review", "npm-v12-remote-tarball-review", "Dependency metadata references a remote tarball URL.", relative, "npm v12 requires explicit --allow-remote approval for remote URL dependencies.");
      }
      if (/github\.com[:/][^\s"']+|(?:git\+https?|git):\/\/[^\s"']+|github:/i.test(text)) {
        addFinding(findings, "review", "npm-v12-git-dependency-review", "Dependency metadata references a Git dependency source.", relative, "npm v12 requires explicit --allow-git approval for Git dependencies.");
      }
    }

    if (base === ".npmrc") {
      if (/^\s*ignore-scripts\s*=\s*true\s*$/im.test(text)) {
        addFinding(findings, "info", "npm-v12-ignore-scripts-migration-note", ".npmrc uses ignore-scripts=true.", relative, "npm approve-scripts can still list pending approvals, but ignore-scripts takes precedence until removed.");
      }
      if (/^\s*allow-git\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-git", ".npmrc broadly allows Git dependency resolution.", relative, "npm v12 defaults --allow-git to none; keep approvals narrow and intentional.");
      }
      if (/^\s*allow-remote\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-remote", ".npmrc broadly allows remote URL dependency resolution.", relative, "npm v12 defaults --allow-remote to none; keep approvals narrow and intentional.");
      }
      if (/^\s*allow-scripts\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
        addFinding(findings, "review", "npm-v12-broad-allow-scripts", ".npmrc broadly allows install scripts.", relative, "npm v12 moves install-script execution to explicit package approvals.");
      }
    }
  }
}

function checkOperationHighlandAuthStack(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";

  for (const candidate of OPERATION_HIGHLAND_IOC_PATHS) {
    const resolved = mapLinuxPath(targetRoot, candidate);
    if (exists(resolved)) {
      const severity = OPERATION_HIGHLAND_LOWER_CONFIDENCE_PATHS.has(candidate) ? "warning" : "critical";
      addFinding(findings, severity, "operation-highland-ioc-path", "Sygnia Operation Highland / Velvet Ant IOC path exists.", candidate, "Treat as possible Linux authentication-stack compromise. Isolate or snapshot the host, preserve evidence, and validate PAM/OpenSSH from trusted media before rotating credentials.");
    }
  }

  const hashCandidates = new Set([...OPERATION_HIGHLAND_AUTH_FILES, ...OPERATION_HIGHLAND_IOC_PATHS]);
  if (OPERATION_HIGHLAND_SHA1_HASHES.size > 0) {
    for (const candidate of hashCandidates) {
      const resolved = mapLinuxPath(targetRoot, candidate);
      const size = fileSizeBytes(resolved);
      if (!isFile(resolved) || size <= 0 || size > 250 * 1024 * 1024) continue;
      const digest = sha1File(resolved);
      if (OPERATION_HIGHLAND_SHA1_HASHES.has(digest)) {
        addFinding(findings, "critical", "operation-highland-known-sha1", "Known Sygnia Operation Highland / Velvet Ant SHA-1 observed.", `${candidate}: sha1=${digest}`, "Preserve the file and compare package ownership/integrity from a clean environment. Do not trust local credentials until persistence is removed.");
      }
    }
  }

  const roots = [
    homeRelative,
    "/etc",
    "/root",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/share/nginx",
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 30000 - files.length));
    if (files.length >= 30000) break;
  }

  for (const filePath of files) {
    const base = path.basename(filePath);
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;
    const text = readText(filePath);

    if (OPERATION_HIGHLAND_FILE_NAMES.has(base)) {
      addFinding(findings, "warning", "operation-highland-tool-filename", "Operation Highland / Velvet Ant filename appears in scanned host tree.", relative, "Review the file provenance, ownership, package integrity, timestamps, and surrounding persistence before cleanup.");
    }

    if (!text) continue;

    for (const indicator of OPERATION_HIGHLAND_NETWORK_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "critical", "operation-highland-network-indicator", "Operation Highland / Velvet Ant C2 or infrastructure indicator appears in scanned metadata.", `${relative}: ${indicator}`, "Correlate with DNS, proxy, firewall, SSH, and process telemetry. Preserve evidence and avoid credential rotation until persistence has been removed.");
      }
    }

    for (const indicator of OPERATION_HIGHLAND_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "operation-highland-text-indicator", "Operation Highland / Velvet Ant behavior indicator appears in scanned metadata.", `${relative}: ${indicator}`, "Review for backdoored PAM/OpenSSH logging, FastCGI bridge execution, and hidden credential-log paths.");
      }
    }

    for (const indicator of OPERATION_HIGHLAND_PROCESS_MASQUERADE) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "operation-highland-process-masquerade-indicator", "Operation Highland / Velvet Ant process-masquerade marker appears in scanned metadata.", `${relative}: ${indicator}`, "Correlate with process listings, systemd/init entries, shell history, and recovered binaries.");
      }
    }
  }
}

function checkAryStingerEdgeProxy(findings, targetRoot, homePath) {
  for (const candidate of ARYSTINGER_IOC_PATHS) {
    if (exists(mapLinuxPath(targetRoot, candidate))) {
      addFinding(findings, "critical", "arystinger-edge-proxy-artifact-path", "AryStinger edge-device malware artifact path exists.", candidate, "Treat router/NAS or mounted filesystem as compromised. Preserve /tmp/bin artifacts, check for Dropbear on port 2332 or gs-netcat persistence, and replace unsupported edge gear.");
    }
  }

  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  const roots = [
    "/tmp",
    "/var/tmp",
    "/var/log",
    "/etc",
    "/opt",
    "/srv",
    "/root",
    homeRelative,
  ].filter(Boolean);
  const files = [];
  for (const root of roots) {
    files.push(...findWatchFiles(mapLinuxPath(targetRoot, root), 25000 - files.length));
    if (files.length >= 25000) break;
  }

  for (const filePath of files) {
    const text = readText(filePath);
    if (!text) continue;
    const relative = `/${path.relative(targetRoot, filePath).replace(/\\/g, "/")}`;

    for (const indicator of ARYSTINGER_TEXT_INDICATORS) {
      if (text.includes(indicator)) {
        addFinding(findings, "warning", "arystinger-edge-proxy-indicator", "AryStinger router/NAS reconnaissance proxy IOC appears in scanned host metadata.", `${relative}: ${indicator}`, "Correlate with outbound connections to ajb8/auq8/dataexplore/opi7 infrastructure, /tmp/bin binaries, syswapd0 processes, and legacy D-Link/Linksys/QNAP exposure.");
      }
    }

    if (/dropbear[\s\S]{0,120}\b2332\b|iptables[\s\S]{0,120}\b2332\b/i.test(text)) {
      addFinding(findings, "critical", "arystinger-dropbear-2332-persistence", "AryStinger-style Dropbear persistence on fixed port 2332 appears in scanned metadata.", relative, "Inspect listening services and firewall rules on affected edge devices. Retire unsupported devices rather than attempting local cleanup only.");
    }

    if (/curl\s+-sk?L\s+https?:\/\/hgodpcx[.\[](?:ajb8|auq8)|wget[\s\S]{0,120}hgodpcx[.\[]ajb8/i.test(text)) {
      addFinding(findings, "critical", "arystinger-downloader-command", "AryStinger downloader command pattern appears in scanned host metadata.", relative, "Preserve command history/scripts and block related downloader/C2 domains at the edge while replacing or reimaging affected appliances.");
    }
  }
}

function checkTransformersPayload(findings, targetRoot) {
  const payloadPath = mapLinuxPath(targetRoot, "/tmp/transformers.pyz");
  if (!exists(payloadPath) || !isFile(payloadPath)) {
    return;
  }

  const digest = sha256File(payloadPath);
  const severity = KNOWN_HASHES.has(digest) ? "critical" : "warning";
  addFinding(findings, severity, "transformers-pyz-present", "A transformers.pyz payload file exists under /tmp.", `sha256=${digest}`, "Preserve the file and metadata for incident response. Do not execute it.");
}

function checkSecretSurfaces(findings, targetRoot, homePath) {
  const homeRelative = homePath ? stripRoot(homePath, targetRoot) : "";
  if (!homeRelative) {
    return;
  }

  const surfaces = [
    `${homeRelative}/.aws/credentials`,
    `${homeRelative}/.config/gh/hosts.yml`,
    `${homeRelative}/.npmrc`,
    `${homeRelative}/.pypirc`,
    `${homeRelative}/.docker/config.json`,
    `${homeRelative}/.kube/config`,
    `${homeRelative}/.ssh`,
  ];

  const present = surfaces.filter((surface) => exists(mapLinuxPath(targetRoot, surface)));
  if (present.length > 0) {
    addFinding(findings, "review", "developer-secret-surfaces-present", "Developer credential surfaces are present.", present.join(", "), "This tool does not read or print secrets. If payload execution is confirmed, rotate credentials from a clean machine.");
  }
}

function addFinding(findings, severity, id, title, evidence, guidance) {
  findings.push({ severity, id, title, evidence, guidance });
}

function summarize(findings) {
  const summary = { critical: 0, warning: 0, review: 0, info: 0, overall: "info" };
  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] || 0) + 1;
  }
  if (summary.critical > 0) summary.overall = "critical";
  else if (summary.warning > 0) summary.overall = "warning";
  else if (summary.review > 0) summary.overall = "review";
  return summary;
}

function mapLinuxPath(root, linuxPath) {
  const clean = linuxPath.replace(/^\/+/, "").replace(/\//g, path.sep);
  return path.join(root, clean);
}

function stripRoot(inputPath, root) {
  const resolvedInput = path.resolve(inputPath);
  const resolvedRoot = path.resolve(root);
  if (resolvedInput.toLowerCase().startsWith(resolvedRoot.toLowerCase())) {
    const relative = path.relative(resolvedRoot, resolvedInput).replace(/\\/g, "/");
    return `/${relative}`;
  }
  return inputPath.startsWith("/") ? inputPath : `/${inputPath.replace(/\\/g, "/")}`;
}

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (_error) {
    return "";
  }
}

function readDirectoryText(dirPath) {
  let output = "";
  for (const filePath of walkFiles(dirPath)) {
    output += `\n${readText(filePath)}`;
  }
  return output;
}

function walkFiles(dirPath) {
  const files = [];
  if (!exists(dirPath)) return files;
  const stack = [dirPath];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(fullPath);
      else if (entry.isFile()) files.push(fullPath);
    }
  }
  return files;
}

function findDependencyFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && DEPENDENCY_FILE_NAMES.has(entry.name)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findWatchFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", ".venv", "venv"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isWatchFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findNginxConfigFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", ".venv", "venv"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && /(?:^nginx\.conf$|\.conf$)$/i.test(entry.name)) {
        try {
          if (fs.statSync(fullPath).size <= 1024 * 1024) files.push(fullPath);
        } catch (_error) {
          // Ignore unreadable config candidates.
        }
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findHadesFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isHadesWatchFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function findRoundcubeFiles(dirPath, maxFiles) {
  const files = [];
  if (maxFiles <= 0 || !exists(dirPath)) return files;
  const stack = [dirPath];
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", ".venv", "venv"]);
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isRoundcubeCandidateFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function isRoundcubeCandidateFile(fileName, filePath) {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  if (/cve-2025-49113.*\.php$/i.test(fileName) || /roundcube.*49113.*\.php$/i.test(fileName)) return true;
  if (normalized.endsWith("/program/include/iniset.php")) return true;
  if (normalized.endsWith("/program/actions/settings/upload.php")) return true;
  if (!ROUNDCUBE_CANDIDATE_FILE_NAMES.has(fileName)) return false;
  if (ROUNDCUBE_ROOT_HINTS.some((hint) => normalized.includes(hint))) return true;
  return fileName === "composer.json" || fileName === "composer.lock";
}

function isWatchFile(fileName, filePath) {
  if (WATCH_FILE_NAMES.has(fileName)) return true;
  const extension = path.extname(fileName);
  if (!WATCH_FILE_EXTENSIONS.has(extension)) return false;
  try {
    return fs.statSync(filePath).size <= 1024 * 1024;
  } catch (_error) {
    return false;
  }
}

function isDocumentationPath(relativePath) {
  return /\.(?:md|mdx|rst|txt)$/i.test(relativePath);
}

function hasDprkSocketIoLoaderShape(text) {
  const lowered = text.toLowerCase();
  const hasCoreTerms = DPRK_SOCKET_IO_LOADER_TERMS.every((term) => lowered.includes(term));
  if (!hasCoreTerms) return false;

  const hasNetworkLoader = /\b(?:fetch|axios|request)\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\(/i.test(text);
  const hasNodeExecution = /\bchild_process\b|\b(?:spawn|spawnSync|exec|execFile|execSync)\s*\(|\bprocess\.execPath\b|\bnode\s+[^;&|]*0001\.dat\b/i.test(text);
  const hasPayloadWrite = /\b(?:writeFile|writeFileSync|createWriteStream|appendFileSync)\s*\(|\bfs\s*\.\s*(?:writeFile|writeFileSync|createWriteStream)\s*\(/i.test(text);

  return hasNetworkLoader && (hasNodeExecution || hasPayloadWrite);
}

function hasTinyGoWasmHostShape(text) {
  return /wasm_exec\.js|gojs\.syscall\/js|asyncify_(?:start|stop)_(?:unwind|rewind)|new\s+WebAssembly\.(?:Instance|Module)|WebAssembly\.instantiate/i.test(text);
}

function hasGlassWasmLoaderShape(text) {
  const hasWasm = /\.wasm|wasm_exec\.js|WebAssembly\.instantiate|gojs\.syscall\/js|asyncify_(?:start|stop)_(?:unwind|rewind)/i.test(text);
  const hasSolanaDeadDrop = /api\.mainnet\.solana\.com|getSignaturesForAddress|getTransaction|MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr|Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz/i.test(text);
  const hasDownloadExecute = /child_process|execSync|curl\s+-fsSL[\s\S]{0,120}\|\s*bash|powershell[\s\S]{0,80}\b(?:irm|Invoke-RestMethod)\b[\s\S]{0,80}\b(?:iex|Invoke-Expression)\b|windowsHide/i.test(text);
  return hasWasm && (hasSolanaDeadDrop || hasDownloadExecute);
}

function hasRoundcubeInstallSignal(text, relativePath) {
  return relativePath.includes("roundcube")
    || /roundcube\/roundcubemail|rcmail_version|Roundcube Webmail|rcube_session|program\/actions\/settings\/upload\.php/i.test(text);
}

function roundcubeVersionsInText(text) {
  const versions = new Set();
  const patterns = [
    /RCMAIL_VERSION['"]?\s*,\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]/gi,
    /(?:Roundcube Webmail|roundcube\/roundcubemail|roundcubemail)[^0-9]{0,80}([0-9]+\.[0-9]+\.[0-9]+)/gi,
    /["']name["']\s*:\s*["']roundcube\/roundcubemail["'][\s\S]{0,300}?["']version["']\s*:\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']/gi,
    /<name>roundcubemail<\/name>[\s\S]{0,500}?<release>([0-9]+\.[0-9]+\.[0-9]+)<\/release>/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function isRoundcube49113Vulnerable(version) {
  if (compareDottedVersion(version, ROUNDCUBE_VULNERABLE_MIN) < 0) return false;
  if (compareDottedVersion(version, "1.5.0") < 0) return true;
  if (compareDottedVersion(version, "1.6.0") < 0) return compareDottedVersion(version, ROUNDCUBE_15_FIXED) < 0;
  if (compareDottedVersion(version, "1.7.0") < 0) return compareDottedVersion(version, ROUNDCUBE_16_FIXED) < 0;
  return false;
}

function hasRoundcube49113PocShape(text, relativePath) {
  return /cve-2025-49113/i.test(relativePath + "\n" + text)
    && /target_url|username\s+password\s+command|program\/actions\/settings\/upload\.php|_from|php\s+CVE-2025-49113\.php/i.test(text);
}

function hasSplunkInstallSignal(text, relativePath) {
  return relativePath.includes("/splunk/")
    || /Splunk Enterprise|splunkd|SPLUNK_HOME|\/opt\/splunk|etc\/splunk\.version|PostgreSQL Sidecar Service/i.test(text);
}

function splunkEnterpriseVersionsInText(text) {
  const versions = new Set();
  const patterns = [
    /VERSION\s*=\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /Splunk Enterprise[^0-9]{0,80}([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /splunk(?:d)?[^0-9]{0,80}([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(normalizeDottedVersion(match[1]));
    }
  }
  return Array.from(versions);
}

function normalizeDottedVersion(version) {
  const parts = version.split(".");
  while (parts.length < 3) parts.push("0");
  return parts.slice(0, 3).join(".");
}

function hasRedcapSignal(text, relativePath) {
  return relativePath.includes("redcap")
    || /REDCap|redcap_version|Project REDCap|redcap_v[0-9_]+|Clinical Data Interoperability Services/i.test(text);
}

function hasFortinetSignal(text, relativePath) {
  return /fortinet|fortigate|fortios|forticloud|fortiproxy|fortiswitchmanager|ssl[-\s]?vpn/i.test(relativePath + "\n" + text);
}

function ffmpegPackagesFromDpkgStatus(text) {
  const packages = [];
  if (!text) return packages;
  for (const block of text.split(/\n\n+/)) {
    if (!/^Status:\s+install\s+ok\s+installed\s*$/im.test(block)) continue;
    const name = block.match(/^Package:\s*(\S+)/im)?.[1] || "";
    if (!FFMPEG_PIXELSMASH_PACKAGES.some((prefix) => name === prefix || name.startsWith(`${prefix}`))) continue;
    const version = block.match(/^Version:\s*(\S+)/im)?.[1] || "unknown-version";
    packages.push({ name, version });
  }
  return packages;
}

function libssh2PackagesFromDpkgStatus(text) {
  const packages = [];
  if (!text) return packages;
  for (const block of text.split(/\n\n+/)) {
    if (!/^Status:\s+install\s+ok\s+installed\s*$/im.test(block)) continue;
    const name = block.match(/^Package:\s*(\S+)/im)?.[1] || "";
    if (!/^libssh2(?:-\d+|-dev|$)/i.test(name)) continue;
    const version = block.match(/^Version:\s*(\S+)/im)?.[1] || "unknown-version";
    packages.push({ name, version });
  }
  return packages;
}

function shapedPluginVersionsInText(text) {
  const candidates = [
    ["woo-product-slider-pro", /(?:Product Slider Pro for WooCommerce|woo-product-slider-pro)[\s\S]{0,500}?(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi],
    ["testimonial-pro", /(?:Real Testimonials Pro|testimonial-pro)[\s\S]{0,500}?(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi],
    ["smart-show-post-pro", /(?:Smart Post Show Pro|Smart Post Pro|smart-show-post-pro)[\s\S]{0,500}?(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi],
    ["woo-product-slider-pro", /(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\s\S]{0,500}?(?:Product Slider Pro for WooCommerce|woo-product-slider-pro)/gi],
    ["testimonial-pro", /(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\s\S]{0,500}?(?:Real Testimonials Pro|testimonial-pro)/gi],
    ["smart-show-post-pro", /(?:Version|Stable tag|version)\s*[:=]?\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\s\S]{0,500}?(?:Smart Post Show Pro|Smart Post Pro|smart-show-post-pro)/gi],
  ];
  const versions = [];
  for (const [slug, pattern] of candidates) {
    for (const match of text.matchAll(pattern)) {
      versions.push({ slug, version: normalizeDottedVersion(match[1]) });
    }
  }
  return versions;
}

function isShapedPluginAffectedVersion(slug, version) {
  if (slug === "woo-product-slider-pro") return compareDottedVersion(version, "3.5.4") < 0;
  if (slug === "testimonial-pro") return compareDottedVersion(version, "3.2.5") === 0;
  if (slug === "smart-show-post-pro") return compareDottedVersion(version, "4.0.2") < 0;
  return false;
}

function squidPackagesFromDpkgStatus(text) {
  const packages = [];
  if (!text) return packages;
  for (const block of text.split(/\n\n+/)) {
    if (!/^Package:\s*squid(?:-[^\s]+)?\s*$/im.test(block)) continue;
    if (!/^Status:\s+install\s+ok\s+installed\s*$/im.test(block)) continue;
    const name = block.match(/^Package:\s*(\S+)/im)?.[1] || "squid";
    const version = block.match(/^Version:\s*(\S+)/im)?.[1] || "unknown-version";
    packages.push({ name, version });
  }
  return packages;
}

function stripHashComments(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+#.*$/, ""))
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

function squidConfigAllowsFtpSafePort(text) {
  return /^\s*acl\s+Safe_ports\s+port\s+21(?:\s|$)/im.test(text)
    || /^\s*acl\s+Safe_ports\s+port\s+ftp(?:\s|$)/im.test(text);
}

function nginxPackagesFromDpkgStatus(text) {
  const packages = [];
  if (!text) return packages;
  for (const block of text.split(/\n\n+/)) {
    if (!/^Package:\s*nginx(?:[-+][^\s]+)?\s*$/im.test(block)) continue;
    if (!/^Status:\s+install\s+ok\s+installed\s*$/im.test(block)) continue;
    const name = block.match(/^Package:\s*(\S+)/im)?.[1] || "nginx";
    const version = block.match(/^Version:\s*(\S+)/im)?.[1] || "unknown-version";
    packages.push({ name, version });
  }
  return packages;
}

function normalizePackageVersion(version) {
  return String(version || "")
    .replace(/^[0-9]+:/, "")
    .match(/[0-9]+\.[0-9]+(?:\.[0-9]+)?/)?.[0] || "";
}

function isNginx42530Affected(version) {
  return compareDottedVersion(normalizeDottedVersion(version), "1.31.0") >= 0
    && compareDottedVersion(normalizeDottedVersion(version), "1.31.2") < 0;
}

function isNginx42055Affected(version) {
  const normalized = normalizeDottedVersion(version);
  return (compareDottedVersion(normalized, "1.31.1") >= 0 && compareDottedVersion(normalized, "1.31.2") < 0)
    || (compareDottedVersion(normalized, "1.30.0") >= 0 && compareDottedVersion(normalized, "1.30.3") < 0);
}

function nginxHasLargeClientHeaderBuffersOver2m(text) {
  const pattern = /^\s*large_client_header_buffers\s+\d+\s+([0-9]+)([kKmMgG]?)\s*;/gim;
  for (const match of text.matchAll(pattern)) {
    if (parseNginxSizeBytes(match[1], match[2]) > 2 * 1024 * 1024) {
      return true;
    }
  }
  return false;
}

function parseNginxSizeBytes(value, suffix) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  const unit = String(suffix || "").toLowerCase();
  if (unit === "g") return numeric * 1024 * 1024 * 1024;
  if (unit === "m") return numeric * 1024 * 1024;
  if (unit === "k") return numeric * 1024;
  return numeric;
}

function difyVersionsInText(text) {
  const versions = new Set();
  const patterns = [
    /\blanggenius\/dify(?:-[a-z0-9_-]+)?\s*:\s*v?([0-9]+\.[0-9]+\.[0-9]+)/gi,
    /\bDIFY_VERSION\s*[:=]\s*["']?v?([0-9]+\.[0-9]+\.[0-9]+)/gi,
    /\bdify(?:-api|-web|-worker)?[^0-9\n]{0,80}v?([0-9]+\.[0-9]+\.[0-9]+)/gi,
    /\bdify\s*==\s*([0-9]+\.[0-9]+\.[0-9]+)/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function redcapVersionsInText(text, relativePath) {
  const versions = new Set();
  const patterns = [
    /REDCap[^0-9]{0,80}([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /redcap_version['"]?\s*[:=]\s*['"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['"]/gi,
    /VERSION\s*=\s*['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /redcap_v([0-9]+)_([0-9]+)_([0-9]+)/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      if (match.length >= 4) {
        versions.add(`${match[1]}.${match[2]}.${match[3]}`);
      } else {
        versions.add(normalizeDottedVersion(match[1]));
      }
    }
  }
  const pathMatch = relativePath.match(/redcap_v([0-9]+)_([0-9]+)_([0-9]+)/i);
  if (pathMatch) versions.add(`${pathMatch[1]}.${pathMatch[2]}.${pathMatch[3]}`);
  return Array.from(versions);
}

function findJoomlaJceFiles(dirPath, maxFiles) {
  const files = [];
  if (!dirPath || maxFiles <= 0) return files;
  const skipDirs = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage", "node_modules", ".venv", "venv"]);
  const stack = [dirPath];
  const seenDirs = new Set();
  while (stack.length > 0 && files.length < maxFiles) {
    const current = stack.pop();
    if (!current || seenDirs.has(current)) continue;
    seenDirs.add(current);
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && isJoomlaJceCandidateFile(entry.name, fullPath)) {
        files.push(fullPath);
        if (files.length >= maxFiles) break;
      }
    }
  }
  return files;
}

function isJoomlaJceCandidateFile(fileName, filePath) {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  if (JOOMLA_JCE_ROOT_HINTS.some((hint) => normalized.includes(hint))) {
    if (JOOMLA_JCE_CANDIDATE_FILE_NAMES.has(fileName)) return true;
    return /\.(php|xml|json|log|txt|md)$/i.test(fileName);
  }
  if (/cve-2026-48907|joomla.*jce|jce.*joomla|com_jce/i.test(normalized)) return true;
  return false;
}

function hasJoomlaJceInstallSignal(text, relativePath) {
  return JOOMLA_JCE_ROOT_HINTS.some((hint) => relativePath.includes(hint))
    || /Joomla Content Editor|JCE Pro|Widget Factory|com_jce|plugins\/editors\/jce|administrator\/components\/com_jce/i.test(text);
}

function joomlaJceVersionsInText(text, relativePath) {
  const versions = new Set();
  const scopedText = `${relativePath}\n${text}`;
  const patterns = [
    /(?:JCE Pro|Joomla Content Editor|Widget Factory|com_jce)[^0-9]{0,120}([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/gi,
    /<name>[^<]*(?:JCE|Joomla Content Editor)[^<]*<\/name>[\s\S]{0,600}?<version>([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)<\/version>/gi,
    /<version>([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)<\/version>[\s\S]{0,600}?(?:JCE|Joomla Content Editor|com_jce)/gi,
    /["'](?:name|element)["']\s*:\s*["'](?:JCE|com_jce|jce)["'][\s\S]{0,300}?["']version["']\s*:\s*["']([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)["']/gi,
  ];
  for (const pattern of patterns) {
    for (const match of scopedText.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function hasJoomlaJce48907PocOrKevShape(text, relativePath) {
  const haystack = `${relativePath}\n${text}`;
  return /cve-2026-48907/i.test(haystack)
    && /Joomla|JCE|com_jce|profile|upload|PHP|Known Exploited Vulnerabilities|CISA|BOD 26-04/i.test(haystack);
}

function isHadesWatchFile(fileName, filePath) {
  if (isWatchFile(fileName, filePath)) return true;
  if (fileName === "_index.js" || /-setup\.pth$/i.test(fileName) || HADES_NATIVE_EXTENSION_FILES.has(fileName)) return true;
  if (fileName.endsWith(".abi3.so")) return true;
  return false;
}

function isAstroConfigFileName(fileName) {
  return /^astro\.config\.(js|cjs|mjs|ts|mts|cts)$/i.test(fileName);
}

function isOpenClawConfigFileName(fileName) {
  return OPENCLAW_CONFIG_FILES.has(fileName.toLowerCase()) || /^openclaw\.(json|jsonc|yaml|yml|toml)$/i.test(fileName);
}

function shouldHashGentlemenArtifact(fileName) {
  const lower = fileName.toLowerCase();
  return GENTLEMEN_TOOLKIT_FILES.has(fileName) || lower === "psexec.exe" || lower === "gentlemen.bmp" || lower.endsWith(".exe") || lower.endsWith(".bmp");
}

function isGentlemenEdrKillerFileName(fileName) {
  if (GENTLEMEN_EDR_KILLER_FILES.has(fileName)) return true;
  return /^(?:Kasp|FaceIT|Valorant|EAAntiCheat|EASolo|BitD|MB|G11|Symantec)(?:1|2|Light|Clear)\.exe$/i.test(fileName)
    || /^Deletor\.exe$/i.test(fileName);
}

function astroConfigLineHasLoaderSignal(line) {
  return /createRequire|eval\s*\(|Function\s*\(|global\s*(?:\.|\[)|Buffer\.from|https?\.|\.request\s*\(|\.get\s*\(|fetch\s*\(|trongrid|aptoslabs|bsc-dataseed|publicnode/i.test(line);
}

function redactDynatraceToken(token) {
  const parts = token.split(".");
  if (parts.length < 3) return "dt0***";
  return `${parts[0]}.${parts[1]}.<redacted>`;
}

function readOsRelease(text) {
  const result = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!match) continue;
    result[match[1]] = match[2].replace(/^"/, "").replace(/"$/, "");
  }
  return result;
}

function detectArchitecture(targetRoot, kernelRelease) {
  const candidates = [
    readText(mapLinuxPath(targetRoot, "/proc/sys/kernel/arch")),
    readText(mapLinuxPath(targetRoot, "/proc/cpuinfo")),
    kernelRelease,
  ].join("\n");

  if (/aarch64|arm64/i.test(candidates)) return "arm64";
  if (/CPU architecture\s*:\s*(?:8|AArch64)/i.test(candidates)) return "arm64";
  return "";
}

function isArm64Architecture(value) {
  return /^(?:aarch64|arm64)$/i.test(String(value || "").trim());
}

function readKernelConfig(targetRoot, kernelRelease) {
  const candidates = [
    kernelRelease ? `/boot/config-${kernelRelease}` : "",
    "/boot/config",
    kernelRelease ? `/lib/modules/${kernelRelease}/build/.config` : "",
  ].filter(Boolean);
  return candidates
    .map((candidate) => readText(mapLinuxPath(targetRoot, candidate)))
    .filter(Boolean)
    .join("\n");
}

function compareKernelRelease(a, b) {
  const left = tokenizeKernel(a);
  const right = tokenizeKernel(b);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] ?? 0;
    const r = right[i] ?? 0;
    if (typeof l === "number" && typeof r === "number" && l !== r) return l > r ? 1 : -1;
    const ls = String(l);
    const rs = String(r);
    if (ls !== rs) return ls > rs ? 1 : -1;
  }
  return 0;
}

function tokenizeKernel(value) {
  return String(value)
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part));
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function sha1File(filePath) {
  const hash = crypto.createHash("sha1");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function loadHashSet(fileName) {
  try {
    const raw = fs.readFileSync(path.join(__dirname, "..", "data", fileName), "utf8");
    return new Set(JSON.parse(raw));
  } catch (_error) {
    return new Set();
  }
}

function exists(filePath) {
  try {
    fs.accessSync(filePath);
    return true;
  } catch (_error) {
    return false;
  }
}

function isFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (_error) {
    return false;
  }
}

function fileSizeBytes(filePath) {
  try {
    return fs.statSync(filePath).size;
  } catch (_error) {
    return 0;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasAnyTerm(text, terms) {
  return terms.some((term) => text.includes(term));
}

function exposesAllInterfaces(text) {
  return /\b(0\.0\.0\.0|\[::\]|::)\b/.test(text) || /--host\s+0\.0\.0\.0\b/i.test(text);
}

function packageVersionsInText(text, packageName) {
  const escaped = escapeRegExp(packageName);
  const versions = new Set();
  const patterns = [
    new RegExp(`\\b${escaped}\\b\\s*(?:==|===|=|~=|>=|<=|>|<)\\s*["']?([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`\\b${escaped}\\b["']?\\s*[:=]\\s*["']?[^0-9\\n\\r]{0,12}([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`name\\s*=\\s*["']${escaped}["'][\\s\\S]{0,300}?version\\s*=\\s*["']([0-9]+\\.[0-9]+\\.[0-9]+)["']`, "gi"),
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function npmVersionsInText(text) {
  const versions = new Set();
  const patterns = [
    /"packageManager"\s*:\s*"npm@([0-9]+\.[0-9]+\.[0-9]+)"/gi,
    /"npm"\s*:\s*"[^"]*?([0-9]+\.[0-9]+\.[0-9]+)[^"]*"/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function pythonPackageVersionInText(text, packageName, version) {
  const escapedPkg = escapeRegExp(packageName);
  const escapedVersion = escapeRegExp(version);
  const normalized = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*${escapedVersion})`, "im"),
    new RegExp(`${escapedPkg}[^\\n\\r]{0,200}${escapedVersion}`, "i"),
  ];
  return patterns.some((pattern) => pattern.test(normalized));
}

function pythonPackageNameInText(text, packageName) {
  const escapedPkg = escapeRegExp(packageName);
  const normalized = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*[^\\n\\r]+)`, "im"),
    new RegExp(`\\b${escapedPkg}\\b`, "i"),
  ];
  return patterns.some((pattern) => pattern.test(normalized));
}

function isHadesPthBunLoader(text) {
  const hasExecutablePthImport = /^\s*import[ \t]/m.test(text);
  const hasBunBootstrap = matchesAnyPattern(text, [
    ["oven-sh\\/bun\\/releases\\/", "download"],
    ["bun-v\\d+\\.\\d+\\.\\d+"],
    ["bun\\.sh\\/", "install"],
    ["Bun\\/1\\.3\\."]
  ]);
  const hasPythonExecution = /subprocess\.(run|Popen|call)|os\.system|exec\(/i.test(text);
  const hasPythonNetworkFetch = /urllib\.request|urlretrieve|requests\.get|curl\b|wget\b|fetch\(/i.test(text);
  return hasExecutablePthImport && /_index\.js/i.test(text) && hasPythonExecution && (hasBunBootstrap || hasPythonNetworkFetch);
}

function joinParts(...parts) {
  return parts.join("");
}

function matchesAnyPattern(text, patternParts) {
  return patternParts.some((parts) => new RegExp(parts.join(""), "i").test(text));
}

function isVersionInRange(version, inclusiveMin, exclusiveMax) {
  return compareDottedVersion(version, inclusiveMin) >= 0 && compareDottedVersion(version, exclusiveMax) < 0;
}

function compareDottedVersion(a, b) {
  const left = String(a).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = String(b).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] || 0;
    const r = right[i] || 0;
    if (l !== r) return l > r ? 1 : -1;
  }
  return 0;
}

module.exports = {
  scanHost,
  compareKernelRelease,
};
