# TODOS

Items deferred from the MCP-First Bionic Hunter design review (2026-03-24).

---

## ~~TODO-1: Secure credential handling for hunt sessions~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/credential_store.py` — loads credentials from `.env` file (already in `.gitignore`). Values never appear in `repr()`/`str()`, masked output via `get_masked()`, auth header builder via `as_headers()`. 15 tests in `tests/test_credential_store.py`.

**What:** Auth credentials (API keys, cookies, Bearer tokens) passed to `/hunt` or `/autopilot` via Bash env vars or direct input persist in the Claude Code conversation transcript. Anyone with access to `~/.claude/projects/` can read them.

**Why:** This is a security gap — bug bounty hunters handle target auth tokens that grant access to real production accounts. Leaking these via conversation history is a liability.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-2: Safe HTTP method policy for autopilot --yolo mode~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `SafeMethodPolicy` class in `memory/audit_log.py`. Default safe methods: GET/HEAD/OPTIONS. PUT/DELETE/PATCH/POST return `require_approval`. Configurable via `safe_methods` set, disableable via `enabled=False`. 12 tests in `tests/test_safe_method_policy.py`. Integrated into `AutopilotGuard`.

**What:** `/autopilot --yolo` could send PUT/DELETE/PATCH to production endpoints. Even if the target is in-scope, destructive HTTP methods on production data create legal liability and could harm the target.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-3: Circuit breaker for autopilot loop~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `AutopilotGuard` class in `memory/audit_log.py` — integrates existing `CircuitBreaker` + `RateLimiter` + new `SafeMethodPolicy` into a single `check_request()` call. Returns structured decisions: `allow`, `block` (circuit tripped), or `require_approval` (unsafe method). Extracts host from URL automatically. 24 tests in `tests/test_autopilot_guard.py`.

**What:** If autopilot hits repeated errors (403 WAF blocks, rate limit 429s, connection timeouts), it has no mechanism to pause, back off, or stop. It will keep burning requests and potentially trigger IP bans.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-4: Fix hunt.py BASE_DIR path resolution~~ ✅ RESOLVED (2026-04-09)

**Resolution:** `hunt.py` was moved from the repo root into `tools/` as part of the v4.0.0 restructure. `BASE_DIR = os.path.dirname(os.path.abspath(__file__))` now correctly resolves to the `tools/` directory, making `TOOLS_DIR = BASE_DIR` accurate. Output paths (`RECON_DIR`, `FINDINGS_DIR`) use the `BBH_OUTPUT_DIR` env var (defaulting to `~/bug-bounty-outputs`), completely decoupled from repo layout.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-5: Define canonical recon output format + legacy adapter~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/recon_adapter.py` — `ReconAdapter` class reads from nested directory format (canonical), with fallback paths for flat-file compat. `normalize()` creates all missing stubs brain.py expects (priority/, api_specs/, urls/graphql.txt, resolved.txt). Builds prioritized_hosts.json and attack_surface.md from live data. 31 tests in `tests/test_recon_adapter.py`.

**What:** `recon_engine.sh` writes recon output in a nested directory format (`recon/{target}/subdomains.txt`, `recon/{target}/live-hosts.txt`, etc.). The `recon-agent.md` expects flat files. Two conflicting formats with no adapter.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-6: Complete v4.0.0 Feature Set~~ ✅ RESOLVED (2026-04-08)

**Resolution:** Implemented all remaining v4.0.0 components:

### Part 1: Exotic Vulnerability Scanners ✅
- ✅ `tools/dependency_confusion_scanner.py` — internal package hijacking (npm, PyPI, RubyGems, Go)
- ✅ `tools/graphql_deep_scanner.py` — 8 GraphQL attack vectors
- ✅ `tools/ssl_scanner.py` — SSL/TLS config, certs, ciphers, protocols
- ✅ `tools/network_scanner.py` — port scan, service detection, banner grabbing
- ✅ `tools/dns_rebinding_tester.py` — DNS rebinding, localhost bypass, Host header

### Part 2: Kali Linux Integration ✅
- ✅ `tools/kali_integration.py` — unified orchestrator for 40+ Kali tools
- ✅ `tools/kali_tool_detector.py` — tool detection, version checking, install script generation
- ✅ `install_tools.sh` update — added `--with-kali-tools` flag

### Part 3: Context & Token Optimization ✅
- ✅ `tools/token_optimizer.py` — token analyzer, chunker, prioritizer, summarizer
- ✅ `tools/context_manager.py` — context window manager for long sessions

### Part 4: New Commands ✅
- ✅ `commands/exotic.md` — `/exotic` command for 35 exotic vuln classes
- ✅ `commands/kali.md` — `/kali` command for Kali tool integration
- ✅ `commands/deep-scan.md` — `/deep-scan` command for network/SSL/DNS scanning

### Part 5: Documentation Updates ✅
- ✅ `CLAUDE.md` — updated with 9 skills, 16 commands, 14 exotic scanners
- ✅ `CHANGELOG.md` — v4.0.0 entry with comprehensive changelog
- ✅ `TODOS.md` — marked all items complete

**Statistics:**
- Commands: 13 → 16 (+3)
- Skills: 8 → 9 (+1)
- Tools: 20 → 29 (+9)
- Bug classes: 30 → 65 (20 standard web2 + 35 exotic + 10 web3)
- Scanners: 10 → 24 (+14 exotic)

**Source:** v4.0.0 development plan (2026-04-08)

---

## ~~TODO-7: v4.2.0 Feature Set~~ ✅ RESOLVED (2026-04-08)

**Resolution:** Implemented all v4.2.0 components:

### Part 1: New Vulnerability Scanners ✅
- ✅ `tools/cors_scanner.py` — 6 CORS test vectors (origin reflection, null origin, subdomain wildcard, pre-flight, credential exposure, internal network)
- ✅ `tools/ssti_scanner.py` — Universal probe + 10 engine-specific payloads (Jinja2, Twig, Freemarker, ERB, Spring EL, Thymeleaf, EJS, Pug, Handlebars, Mako) + WAF bypass + blind detection
- ✅ `tools/open_redirect_scanner.py` — 18 params, 30+ bypass techniques, OAuth chain detection, full redirect chain following

### Part 2: Token Optimization Enhancements ✅
- ✅ `tools/token_optimizer.py` — `--dedup` (Jaccard similarity), `--compress` (strip comments/blanks/docstrings), `--budget N` (priority-ordered file selection), improved `estimate_tokens()` (hybrid char+word)

### Part 3: Context Manager Enhancements ✅
- ✅ `tools/context_manager.py` — `--auto-compact` (triggers at 80%), `--snapshot`/`--restore`/`--diff` (named snapshots), `get_item_content()` (lazy loading), `get_item_metadata_only()`

### Part 4: Integrity Testing ✅
- ✅ `tests/test_new_scanners.py` — 15 tests for 3 new scanners
- ✅ `tests/test_token_optimizer_enhanced.py` — 13 tests for new token_optimizer features
- ✅ `tests/test_context_manager_enhanced.py` — 12 tests for new context_manager features
- ✅ `tests/test_core_integrity.py` — 16 tests: imports, CLI help, memory modules, test count

### Part 5: Documentation Updates ✅
- ✅ `skills/exotic-vulns/SKILL.md` — Added classes 56 (CORS), 57 (SSTI), 58 (Open Redirect)
- ✅ `commands/exotic.md` — Scanner table updated 14 → 17 scanners
- ✅ `CLAUDE.md` — New scanners added to tool lists
- ✅ `CHANGELOG.md` — v4.2.0 entry
- ✅ `README.md` — v4.2.0 badge, statistics, What's New section
- ✅ `TODOS.md` — This entry

**Statistics:**
- Scanners: 14 exotic → 17 exotic (+3); Web scanners: 7 → 10 (+3)
- Bug classes: 55 web2 → 58 web2 (+3 new exotic classes)
- Tools: 29 → 32 (+3)
- Tests: 211 → 267 (+56 new tests)

**Source:** v4.2.0 development plan (2026-04-08)

---

## Active TODOs (None)

---

## ~~TODO-8: Fix test collection errors for test_credential_store + test_recon_adapter~~ ✅ RESOLVED (2026-04-09)

**Resolution:** Added `tools/__init__.py` to make the `tools/` directory a proper Python package. Both test files import via `from tools.credential_store import CredentialStore` / `from tools.recon_adapter import ReconAdapter`, which requires the package marker. The `memory/` directory already had `memory/__init__.py` for the same reason. All 222 tests now pass (previously 220 collected with 2 collection errors).

**What:** `tests/test_credential_store.py` and `tests/test_recon_adapter.py` raised `ModuleNotFoundError: No module named 'tools.credential_store'` during test collection. pytest could not even discover the 31 + 15 = 46 tests in those files.

**Why:** `tools/` lacked an `__init__.py`, so Python couldn't treat it as a package, breaking `from tools.X import Y` style imports while `from memory.X import Y` (which has `__init__.py`) worked fine.

**Source:** Verification run (2026-04-09)
