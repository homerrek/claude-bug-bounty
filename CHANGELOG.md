# Changelog

## v4.2.1 — Bug Fixes + Documentation (Apr 2026)

### Fixed

- **`tools/__init__.py`**: Added package marker so `from tools.credential_store import CredentialStore` and `from tools.recon_adapter import ReconAdapter` resolve correctly in the test suite. Previously `test_credential_store.py` and `test_recon_adapter.py` raised `ModuleNotFoundError` at collection time, hiding 46 tests. All **222 tests** now pass.

### Documentation

- **`TODOS.md`**: Marked TODO-4 (BASE_DIR path resolution) as ✅ RESOLVED — the bug was implicitly fixed when `hunt.py` was relocated from the repo root into `tools/` during v4.0.0. Added TODO-8 entry documenting the `tools/__init__.py` fix.

---

## v4.2.0 — New Scanners + Token Optimization + Integrity Testing (Apr 2026)

### Added — 3 New Vulnerability Scanners

- **`tools/cors_scanner.py`**: Comprehensive CORS misconfiguration scanner — 6 test vectors: origin reflection, null origin (sandboxed iframe bypass), subdomain wildcard acceptance, pre-flight bypass, credential exposure (`ACAO` reflected + `ACAC: true` → CRITICAL), internal network origins. Supports `--target`, `--url-list`, `--rate`, `--json`, `--dry-run`.
- **`tools/ssti_scanner.py`**: Server-Side Template Injection scanner — universal detection probe (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{7*7}`, `${{7*7}}`), engine-specific payloads for 10 engines (Jinja2, Twig, Freemarker, ERB, Spring EL, Thymeleaf, EJS, Pug, Handlebars, Mako), WAF bypass variants (URL-encoding, unicode, concatenation), blind/time-based detection. Auto-identifies template engine from successful probes. Supports `--target`, `--url-list`, `--param`, `--rate`, `--json`, `--dry-run`.
- **`tools/open_redirect_scanner.py`**: Open Redirect scanner — 18 common redirect parameters, 30+ bypass techniques (protocol-relative, backslash, at-sign, URL encoding, double encoding, tab/newline injection, fragment bypass, parameter pollution, Unicode normalization), full redirect chain following with meta-refresh/JS redirect detection, special attention to `redirect_uri` for OAuth chains. Supports `--target`, `--url-list`, `--rate`, `--json`, `--dry-run`.

### Enhanced — Token Optimizer (`tools/token_optimizer.py`)

- **`--dedup`**: Scan a directory for duplicate/near-duplicate content using Jaccard similarity on word 3-grams. Reports file pairs with >80% overlap and suggests consolidation.
- **`--compress`**: Strip comments, blank lines, and Python docstrings from a file while preserving functional code. Output saved to `{original}_compressed.py` for context loading (does not replace source).
- **`--budget N`**: Given a token budget, automatically select highest-priority files from a directory (CRITICAL → HIGH → MEDIUM → LOW order) that fit within budget.
- **Improved `estimate_tokens()`**: Hybrid char+word estimate — `(char_estimate + word_count * 1.3) / 2` — closer to actual BPE tokenization than pure character division.

### Enhanced — Context Manager (`tools/context_manager.py`)

- **`--auto-compact`**: Automatically trigger compaction when context usage exceeds 80% after adding an item (instead of requiring manual `--compact`).
- **`--snapshot NAME`**: Save a named snapshot of current context state for later restore. Useful for branching hunt sessions.
- **`--restore NAME`**: Restore a previously saved snapshot.
- **`--diff NAME_A NAME_B`**: Show what changed (added/removed/priority-changed items) between two snapshots.
- **`get_item_content(item_id)`**: Load full item content on demand (lazy loading architecture).
- **`get_item_metadata_only()`**: Returns item list without content fields for lightweight display.

### Added — 4 New Test Files

- **`tests/test_new_scanners.py`** (15 tests): CLI arg parsing, dry-run makes no HTTP requests, payload generation, JSON output format, graceful connection error handling — for all 3 new scanners.
- **`tests/test_token_optimizer_enhanced.py`** (13 tests): dedup detection, compress accuracy, budget selection, improved `estimate_tokens()`, backward compatibility for existing `--analyze`/`--chunk`/`--summarize`.
- **`tests/test_context_manager_enhanced.py`** (12 tests): auto-compact triggers at 80%, snapshot save/restore/diff, lazy loading metadata, `get_item_content()`.
- **`tests/test_core_integrity.py`** (16 tests): all key tools import without error, all scanners accept `--help` (exit 0), memory modules instantiate, test suite count validation.

### Updated — Documentation

- **`skills/exotic-vulns/SKILL.md`**: Added sections for bug classes 56 (CORS deep), 57 (SSTI), and 58 (Open Redirect) with full root-cause analysis, bypass tables, RCE payload examples, and scanner references.
- **`commands/exotic.md`**: Updated scanner table from 14 → 17 scanners, description updated to 38 bug classes.
- **`CLAUDE.md`**: Added 3 new scanners to Web Scanners list, updated exotic-vulns skill description to 38 classes.
- **`README.md`**: Version badge v4.0.0 → v4.2.0, statistics updated.
- **`TODOS.md`**: Added TODO-7 entry (v4.2.0 resolved).

### Statistics

- **Bug classes**: 55 web2 + 10 web3 → **58 web2 + 10 web3 = 68 total** (+3)
- **Scanners**: 14 exotic → **17 exotic** (+3 new); Web scanners: 7 → **10** (+3)
- **Tools**: 29 → **32** (+3)
- **Tests**: 211 existing → **267 total** (+56 new tests across 4 new files)

---

## v4.0.0 — Exotic Vulns + Kali Integration + Context Optimization (Apr 2026)

### Major: Exotic Vulnerability Hunting (35 Bug Classes)
- **New Skill**: `skills/exotic-vulns/SKILL.md` — 35 exotic vuln classes (21-55): JWT attacks, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, CORS deep, insecure randomness, LDAP injection, NoSQL expanded, rate limit bypass advanced, clickjacking advanced, CRLF injection, web cache deception, server-side prototype pollution, postMessage XSS, CSS injection, dangling markup, ESI injection, PDF SSRF, email header injection, subdomain delegation takeover, OAuth token theft via Referer, timing side channels, integer overflow, ReDoS, host header poisoning expanded, GraphQL deep, dependency confusion, client-side desync, HTTP parameter pollution, mass assignment, path traversal expanded, WebSocket IDOR

### Added — 14 Exotic Vulnerability Scanners
- **`tools/dependency_confusion_scanner.py`**: Detects internal packages vulnerable to hijacking via public registries (npm, PyPI, RubyGems). Scans package.json, requirements.txt, Gemfile, go.mod. Identifies internal naming patterns and checks public registry availability.
- **`tools/graphql_deep_scanner.py`**: 8 GraphQL attack vectors — introspection enabled, field suggestions, batch query attacks, nested query DoS, alias-based rate limit bypass, circular fragments DoS, directive abuse, mutations without auth.
- **`tools/ssl_scanner.py`**: SSL/TLS configuration scanner — certificate validity/expiration, chain verification, SAN validation, protocol versions (SSLv2/v3, TLS 1.0-1.3), cipher suites, key strength, compression (CRIME).
- **`tools/network_scanner.py`**: Port scanning, service detection, banner grabbing. Tests for dangerous services (FTP, Telnet, RDP, Redis, MongoDB, Elasticsearch), version disclosure, unauthenticated access (Redis `INFO` command, MongoDB connection test).
- **`tools/dns_rebinding_tester.py`**: DNS rebinding attack detector — localhost/127.0.0.1 bypass in URL params, Host header manipulation, multiple IP resolution (round-robin DNS), internal service probing, cloud metadata access (AWS, GCP).
- **Existing scanners integrated**: `jwt_scanner.py`, `proto_pollution_scanner.py`, `deserial_scanner.py`, `xxe_scanner.py`, `websocket_scanner.py`, `host_header_scanner.py`, `timing_scanner.py`, `postmessage_scanner.py`, `css_injection_scanner.py`, `esi_scanner.py`

### Added — Kali Linux Integration
- **`tools/kali_integration.py`**: Unified orchestrator for 40+ Kali security tools. Pre-configured tool profiles (web, network, webapp, password, enumeration, full). Automatic output parsing and finding aggregation. Supports: nmap, nikto, dirb, gobuster, sqlmap, whatweb, wpscan, masscan, enum4linux, hydra, john, hashcat, burpsuite, zaproxy.
- **`tools/kali_tool_detector.py`**: Detects installed Kali tools, checks versions, validates configurations. Generates installation scripts for missing tools. Supports apt (Debian/Ubuntu/Kali), Go install, and custom installers. Tool health checker with priority flags (CRITICAL/HIGH/MEDIUM/LOW).
- **`install_tools.sh`**: Added `--with-kali-tools` flag to install Kali integration scripts to `/usr/local/bin` or `~/bin`.

### Added — Context & Token Management
- **`tools/token_optimizer.py`**: Token usage analyzer and optimizer. Features: directory analysis (top token consumers), file chunking (splits large files into safe chunks), content prioritization (CRITICAL/HIGH/MEDIUM/LOW based on keywords), summarization (extracts URLs, IPs, domains, endpoints).
- **`tools/context_manager.py`**: Context window manager for long hunt sessions. Features: session persistence, item prioritization (auto-downgrade by age), context compaction (removes low-priority old items), token budget allocation (system 5%, memory 15%, findings 30%, recon 25%, conversation 25%), export to JSON.

### Added — New Commands
- **`/exotic`**: Hunt 35 exotic vulnerability classes with 14 specialized scanners. Profiles: `--profile quick` (6 scanners, 5-10 min), `--profile deep` (all 14, 20-30 min), `--scanner <name>` (single scanner). Integrates with `/validate` for findings.
- **`/kali`**: Integrate Kali Linux tools. Profiles: `web` (nikto, sqlmap, dirb, gobuster, wpscan), `network` (nmap, masscan), `webapp` (burp, zap, sqlmap), `password` (john, hashcat, hydra), `enumeration` (enum4linux, smbclient), `full` (comprehensive). Supports `--detect` to list tools, `--install-missing` to generate install script.
- **`/deep-scan`**: Deep network, SSL/TLS, and DNS rebinding scanning with custom Python tools. Profiles: `fast` (top 20 ports), `full` (top 1000 ports), `--scanner ssl` (SSL only), `--scanner dns` (DNS rebinding only). Complements `/kali` with deeper analysis.

### Changed — Documentation
- **CLAUDE.md**: Updated to reflect 9 skills (added `exotic-vulns`), 16 commands (added `/exotic`, `/kali`, `/deep-scan`), 14 exotic scanners, Kali integration, context management tools.
- **README.md**: Updated with v4.0.0 features, badge, statistics, and new command references
- **TODOS.md**: Marked completed items (scanner suite, Kali integration, token optimization, command additions)

### Technical Improvements
- **No external dependencies for new scanners**: All 5 new scanners (`dependency_confusion_scanner.py`, `graphql_deep_scanner.py`, `ssl_scanner.py`, `network_scanner.py`, `dns_rebinding_tester.py`) use Python stdlib only — no pip installs required.
- **Parallel execution**: `network_scanner.py` uses ThreadPoolExecutor for concurrent port scanning (default: 10 threads, configurable).
- **Rate limiting**: All scanners support `--rate` parameter for request throttling (default: 1 req/sec).
- **JSON output**: All tools support `--json` flag for machine-readable output.
- **Dry-run mode**: Host header, dependency confusion, and DNS rebinding testers support `--dry-run` to preview tests without sending requests.

### Statistics
- **Commands**: 13 → 16 (+3)
- **Skills**: 8 → 9 (+1)
- **Exotic vulnerability scanners**: 0 → 14 (+14, plus 5 new from scratch)
- **Tools**: 20 → 29 (+9)
- **Bug classes covered**: 20 web2 + 10 web3 → 55 web2 (20 standard + 35 exotic) + 10 web3 = **65 total**

---

## v3.1.1 — CI/CD GitHub Actions Security Expansion (Mar 2026)

### Changed — Existing Skill Enhancement
- `SKILL.md` CI/CD Pipeline section: **5 checklist items → 6 categories, 30+ checks, PoC templates, hunting workflow, and GHSA reference table**
  - **Category 1: Code Injection & Expression Safety** — expression injection, envvar/envpath/output clobbering, argument injection, SSRF via workflow, taint source catalog, fix patterns (env var extraction, heredoc delimiters, end-of-options markers)
  - **Category 2: Pipeline Poisoning & Untrusted Checkout** — untrusted checkout on `pull_request_target`/`workflow_run`, TOCTOU with label-gated approvals, reusable workflow taint, cache poisoning, artifact poisoning, artipacked credential leakage
  - **Category 3: Supply Chain & Dependency Security** — unpinned actions (tag → SHA), impostor commits from fork network, ref confusion, known vulnerable actions, archived actions, unpinned container images
  - **Category 4: Credential & Secret Protection** — secret exfiltration, secrets in artifacts, unmasked `fromJson()` bypass, excessive `secrets: inherit`, hardcoded credentials
  - **Category 5: Triggers & Access Control** — dangerous triggers without/with partial mitigation, label-based approval bypass, bot condition spoofing, excessive GITHUB_TOKEN permissions, self-hosted runners in public repos, OIDC token theft
  - **Category 6: AI Agent Security** — unrestricted AI triggers, excessive tool grants to AI agents, prompt injection via workflow context
  - **Hunting workflow** — 6-step recon→scan→triage→verify→PoC→prove pipeline
  - **Expression injection PoC template** — ready-to-use `gh issue create` payload
  - **10 real-world GHSAs** — proven Critical/High advisories with affected actions
  - **A→B signal chains** — 7 CI/CD-specific escalation paths
  - **Tooling**: integrated [sisakulint](https://sisaku-security.github.io/lint/) — 52 rules, taint propagation, 81.6% GHSA coverage
  - **Deep-dive guide**: Decision tree for verifying sisakulint findings based on 36 real-world paid reports (Bazel $13K, Flank $7.5K, PyTorch $5.5K, GitHub $20K, DEF CON $250K+)

### Added — Tool Integration
- `tools/cicd_scanner.sh`: standalone sisakulint wrapper — org/repo scanning, recursive reusable workflow analysis, parsed summary output with per-rule breakdown
- `install_tools.sh`: sisakulint binary auto-download with OS/arch detection (v0.2.11, linux/darwin, amd64/arm64/armv6), cicd_scanner install now optional (`--with-cicd-scanner`)
- `tools/recon_engine.sh` Phase 8: auto-detects GitHub orgs from recon data (httpx, JS endpoints, URLs), invokes `cicd_scanner.sh` per org
- `tools/hunt.py`: surfaces CI/CD findings between recon and vuln scan stages via `check_cicd_results()`
- `tests/test_cicd_scanner.sh`: shell tests for cicd_scanner (syntax check + CLI behavior)

## v3.1.0 — Hunting Methodology Skill (Mar 2026)

### Added — New Skill Domain
- `skills/bb-methodology/SKILL.md`: **Hunting mindset + 5-phase non-linear workflow** — the "HOW to think" layer that was missing from the toolkit
  - **Part 1: Mindset** — Define/Select/Execute discipline, 4 thinking domains (critical, multi-perspective, tactical, strategic), developer psychology reverse-engineering, Amateur vs Pro 7-phase comparison, Feature-based vs Vuln-based route selection, anti-patterns
  - **Part 2: Workflow** — 5-phase non-linear flow (Recon → Map → Find → Prove → Report) with decision trees per phase, input-type → vuln-class routing, Error vs Blind detection cascade, escalation decision trees per vuln class
  - **Part 3: Navigation & Timing** — "I'm stuck because..." quick reference table, 20-minute rotation clock, tool routing by phase with rationale, session start/end checklists

### Changed
- `CLAUDE.md`: Skills count 7 → 8, added `bb-methodology` to skill table
- `README.md`: Updated skill domain count to 8
- `SKILL.md`: Added cross-reference to `bb-methodology` after CRITICAL RULES section

## v2.1.0 — 20 Vuln Classes + Payload Expansion (Mar 2026)

### Config
- Recon commands now read the Chaos API key from the `$CHAOS_API_KEY` environment variable for cleaner setup across different environments.

### Added — New Vuln Classes
- `web2-vuln-classes`: **MFA/2FA Bypass** (class 19) — 7 bypass patterns: rate limit, OTP reuse, response manipulation, workflow skip, race, backup codes, device trust escalation
- `web2-vuln-classes`: **SAML/SSO Attacks** (class 20) — XML signature wrapping (XSW), comment injection, signature stripping, XXE in assertion, NameID manipulation + SAMLRaider workflow

### Added — security-arsenal Payloads
- **NoSQL injection**: MongoDB `$ne`/`$gt`/`$regex`/`$where` operators, URL-encoded GET parameter injection
- **Command injection**: Basic probes, blind OOB (curl/nslookup), space/keyword bypass techniques, Windows payloads, filename injection context
- **SSTI detection**: Universal probe for all 6 engines (Jinja2, Twig, Freemarker, ERB, Spring, EJS) + RCE payloads for each
- **HTTP smuggling payloads**: CL.TE, TE.CL, TE.TE obfuscation variants, H2.CL
- **WebSocket testing**: IDOR/auth bypass messages, CSWSH PoC, Origin validation test, injection via messages
- **MFA bypass payloads**: OTP brute force (ffuf), race async script, response manipulation, device trust cookie test
- **SAML attack payloads**: XSW XML templates, comment injection, signature stripping workflow, XXE payload, SAMLRaider CLI

### Added — web2-recon Skill
- **Setup section**: `$CHAOS_API_KEY` export instructions, subfinder config.yaml with 5 API sources, nuclei-templates update command
- **crt.sh** passive subdomain source (no API key needed) added as Step 0
- **Port scanning**: naabu command for non-standard ports (8080/8443/3000/9200/6379/etc.)
- **Secret scanning**: trufflehog + SecretFinder JS bundle scan, grep patterns
- **GitHub dorking**: `gh search code` commands, GitDorker integration for org-wide secret search

### Added — report-writing Skill
- **Intigriti template**: Full format with platform-specific notes (video PoC preference, safe harbor stance)
- **CVSS 4.0 quick reference**: Key differences from CVSS 3.1, score examples for common findings, calculator link

### Added — rules/hunting.md
- **Rule 18**: Mobile = different attack surface (APK decompile workflow, key targets)
- **Rule 19**: CI/CD is attack surface (GitHub Actions expression injection, dangerous workflow patterns)
- **Rule 20**: SAML/SSO = highest auth bug density (test checklist)

### Updated
- README: CHAOS_API_KEY setup section with free key instructions and optional subfinder API keys
- README: Updated vuln class count from 18 → 20, updated skill descriptions
- `web2-vuln-classes` description updated to reflect 20 classes and new additions

---

## v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

Major restructure into a full Claude Code plugin with multi-component architecture.

### Added
- `skills/` directory with 7 focused skill domains (split from monolithic SKILL.md)
  - `skills/bug-bounty/` — master workflow (unchanged from v1)
  - `skills/web2-recon/` — recon pipeline, subdomain enum, 5-minute rule
  - `skills/web2-vuln-classes/` — 18 bug classes with bypass tables
  - `skills/security-arsenal/` — payloads, bypass tables, never-submit list
  - `skills/web3-audit/` — 10 smart contract bug classes, Foundry template
  - `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi templates
  - `skills/triage-validation/` — 7-Question Gate, 4 gates, always-rejected list
- `commands/` directory with 8 slash commands
  - `/recon` — full recon pipeline
  - `/hunt` — start hunting a target
  - `/validate` — 4-gate finding validation
  - `/report` — submission-ready report generator
  - `/chain` — A→B→C exploit chain builder
  - `/scope` — asset scope verification
  - `/triage` — quick 7-Question Gate
  - `/web3-audit` — smart contract audit
- `agents/` directory with 5 specialized agents
  - `recon-agent` — runs recon pipeline, uses claude-haiku-4-5 for speed
  - `report-writer` — generates reports, uses claude-opus-4-6 for quality
  - `validator` — validates findings, uses claude-sonnet-4-6
  - `web3-auditor` — audits contracts, uses claude-sonnet-4-6
  - `chain-builder` — builds exploit chains, uses claude-sonnet-4-6
- `hooks/hooks.json` — session start/stop hooks with hunt reminders
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)
- `CLAUDE.md` — plugin overview and quick-start guide
- `install.sh` — one-command skill installation

### Content Added to Skills
- SSRF IP bypass table: 11 techniques (decimal, octal, hex, IPv6, redirect chain, DNS rebinding)
- Open redirect bypass table: 11 techniques for OAuth chaining
- File upload bypass table: 10 techniques + magic bytes reference
- Agentic AI ASI01-ASI10 table: OWASP 2026 agentic AI security framework
- Pre-dive kill signals for web3: TVL formula, audit check, line-count heuristic
- Conditionally valid with chain table: 12 entries
- Report escalation language for payout downgrade defense

---

## v1.0.0 — Initial Release (Early 2026)

- Monolithic SKILL.md (1,200+ lines) covering full web2+web3 workflow
- Python tools: `hunt.py`, `learn.py`, `validate.py`, `report_generator.py`, `mindmap.py`
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`
- Shell tools: `recon_engine.sh`, `vuln_scanner.sh`
- Utilities: `sneaky_bits.py`, `target_selector.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- Web3 skill chain: 10 files in `web3/` directory
- Wordlists: 5 wordlists in `wordlists/` directory
- Docs: `docs/payloads.md`, `docs/advanced-techniques.md`, `docs/smart-contract-audit.md`
