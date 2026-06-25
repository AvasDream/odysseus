# Odysseus — Deep Correctness & Security Audit

**Synthesis dashboard across 12 area reports.** No Critical findings. 2 High, 7 Medium, 3 Low (12 total). 2 candidate findings were dropped as false positives during independent verification.

---

## Methodology

1. **Parallel per-area finders.** Twelve area-scoped agents independently traced control and data flow across their assigned subsystems (authz, injection/SSRF, prompt-injection, concurrency, in-memory state, persistence, networking/streaming, caching/RAG, numeric/temporal, tools/MCP, email, secrets/lifecycle).
2. **Independent adversarial verification.** Every candidate finding was re-examined by a separate adversarial pass that attempted to falsify it (find the missing guard, the upstream check, the accepted-tradeoff framing). Candidates that did not survive were dropped as **false positives** (2 dropped: 1 in caching, 1 in email).
3. **Per-area reports.** Survivors were written up as self-contained per-area reports (Markdown + HTML) with confidence, location, invariant violated, trigger, fix direction, and root-cause tag.
4. **Synthesis (this dashboard).** Per-area results aggregated here: severity rollup, global ranking, systemic patterns clustered by root cause across areas, and a coverage map.

> Note: the `/visual-explainer` skill was **unavailable** in this environment, so equivalent self-contained HTML reports were produced by hand with a single shared stylesheet. All analysis is **static** control/data-flow tracing — the application was not dynamically executed.

---

## Severity rollup (all areas)

| Critical | High | Medium | Low | **Total** |
|:--------:|:----:|:------:|:---:|:---------:|
| 0 | 2 | 7 | 3 | **12** |

False positives dropped during verification: **2**.

---

## Global ranking — most serious issues

Sorted Critical → High → Medium → Low. Title links to the area report.

| # | Severity | Title | Location | Area | One-line |
|---|----------|-------|----------|------|----------|
| 1 | **High** | [Compaction summarizes untrusted content and re-injects it as a trusted system message](areas/prompt-injection.md) | `src/context_compactor.py:336-417` | prompt-injection | Summarizer strips the untrusted wrapper, then emits the output as a bare `role='system'` message — laundering injected text into the trusted system role. |
| 2 | **High** | [Compaction persists corrupted history (system-msg count used as offset into session.history)](areas/state.md) | `src/context_compactor.py:336-342,409,420-456` | state | Preface system-message count is applied as a leading-system offset into a history that has no preface, silently dropping ≥1 recent turn and mislabeling a user turn as system on every compaction. |
| 3 | Medium | [Research 'Discuss' spin-off seeds web-derived report into a system-role primer](areas/prompt-injection.md) | `routes/research_routes.py:654-669` | prompt-injection | Web-derived report is embedded verbatim into a never-trimmed `role='system'` message, so surviving injections become authoritative system instructions. |
| 4 | Medium | [Auto-poller executes calendar create/update/cancel from untrusted email body](areas/prompt-injection.md) | `routes/email_pollers.py:513-611` | prompt-injection | Inbound email body drives the calendar-extraction LLM with no untrusted wrapper, and parsed delete/update ops are auto-applied with no confirmation. |
| 5 | Medium | [CancelledError in `_cached()` owner poisons shared singleflight cache key](areas/concurrency.md) | `src/task_scheduler.py:60-94` | concurrency | Owner cleanup lives only in `except Exception`, missing CancelledError; a Stop mid-fetch hangs all waiters of a process-global cross-user cache key forever. |
| 6 | Medium | [Memory audit silently drops memories added during its LLM window](areas/persistence.md) | `services/memory/memory_extractor.py:508-639` | persistence | Snapshot → 30-120s LLM call → write-back from the stale snapshot clobbers same-owner rows added during the unlocked read-modify-write window. |
| 7 | Medium | [Manual compaction reorders the conversation on reload](areas/persistence.md) | `routes/history_routes.py:584-642` | persistence | Summary rows get `timestamp=now` while kept rows retain earlier timestamps, so a timestamp-ordered DB reload sinks summaries to the end, corrupting the transcript. |
| 8 | Medium | [Scheduled email delivered before the row is claimed/marked sent](areas/email.md) | `routes/email_pollers.py:1010-1085` | email | `status='sent'` flips only after the irreversible SMTP send, so a crash or dual poller re-selects the pending row and re-delivers to all recipients. |
| 9 | Medium | [HuggingFace token written in plaintext into world-readable /tmp wrapper scripts](areas/secrets-lifecycle.md) | `routes/cookbook_routes.py:523,550,801-802` | secrets-lifecycle | `export HF_TOKEN` is written into a `0o755` wrapper in shared `/tmp/odysseus-tmux`; any local OS user can read the admin's gated-repo token, and the serve path never self-deletes it. |
| 10 | Low | [Orphaned tool-execution subprocess task on agent-turn cancellation](areas/concurrency.md) | `src/agent_loop.py:3104-3133` | concurrency | Awaiting `_tool_task` doesn't cancel it; on Stop/disconnect the bash/python subprocess runs unconsumed until the 3600s timeout. |
| 11 | Low | [Cancelled background HTTP MCP connect leaks its AsyncExitStack](areas/concurrency.md) | `src/mcp_manager.py:325-378` | concurrency | A CancelledError before the stack is stored leaves the entered httpx transport + anyio task group never `aclose()`'d (admin-only, finite). |
| 12 | Low | [Check-in calendar window strips timezone instead of converting to UTC](areas/numeric-temporal.md) | `src/task_scheduler.py:1205-1227` | numeric-temporal | tz-aware LOCAL bounds are `.replace(tzinfo=None)`'d to naive-LOCAL instead of naive-UTC, shifting digest buckets by the owner's UTC offset for non-UTC owners. |

---

## Per-area results

| Area | C | H | M | L | Report | Top coverage gap |
|------|:-:|:-:|:-:|:-:|--------|------------------|
| Authentication, Authorization, Sessions & Tokens | 0 | 0 | 0 | 0 | [md](areas/authz.md) · [html](areas/authz.html) | Full per-route IDOR audit of ~40 routers not exhaustive (spot-checked owner gates all enforce effective_user/api_token_owner). |
| Injection Sinks & SSRF | 0 | 0 | 0 | 0 | [md](areas/injection-ssrf.md) · [html](areas/injection-ssrf.html) | DNS-rebinding TOCTOU present-but-accepted in all three SSRF validators (host resolved at validation, httpx re-resolves at connect). |
| Agent Trust Boundary & Prompt-Injection | 0 | 1 | 2 | 0 | [md](areas/prompt-injection.md) · [html](areas/prompt-injection.html) | MCP native tool_calls path appends `role='tool'` result_text unwrapped; injection-resistance relies on the model treating tool results as data. |
| Concurrency, Async Safety, Races & Cancellation | 0 | 0 | 1 | 2 | [md](areas/concurrency.md) · [html](areas/concurrency.html) | Not every task_scheduler executor branch traced for additional CancelledError leaks beyond `_cached`. |
| In-Memory State Management & Invariants | 0 | 1 | 0 | 0 | [md](areas/state.md) · [html](areas/state.html) | Stream-cancellation 'stopped' paths not fully reconciled against compaction state for partial-history persistence. |
| Persistence, Transactions, Durability & Migrations | 0 | 0 | 2 | 0 | [md](areas/persistence.md) · [html](areas/persistence.html) | ~40 init_db() migrations not exhaustively traced for column-default backfill correctness. |
| Networking, Streaming, Retry/Backoff, Timeouts | 0 | 0 | 0 | 0 | [md](areas/networking-streaming.md) · [html](areas/networking-streaming.html) | agent_loop stream `break` relies on refcount/async-gen finalizer to aclose() the httpx connection; GC timing not instrumented. |
| Caching, Invalidation, RAG & Embeddings | 0 | 0 | 0 | 0 | [md](areas/caching.md) · [html](areas/caching.html) | ChromaDB not exercised at runtime; relied on documented dimension-mismatch contract. |
| Numeric & Temporal Correctness, Scheduling | 0 | 0 | 0 | 1 | [md](areas/numeric-temporal.md) · [html](areas/numeric-temporal.html) | DST transition in compute_next_run tz path not exhaustively traced (≤ twice-yearly 1h drift). |
| Tool Parsing, Execution & MCP Subprocess Lifecycle | 0 | 0 | 0 | 0 | [md](areas/tools-mcp.md) · [html](areas/tools-mcp.html) | Could not confirm whether read-only list_served_models / tail_serve_output are surfaced to non-admins (possible low-sev info leak). |
| Email Subsystem: IMAP/SMTP, Parsing & Pollers | 0 | 0 | 1 | 0 | [md](areas/email.md) · [html](areas/email.html) | check_email_urgency alert-send sink not fully traced for header injection. |
| Secrets, Resource Leaks, Process/Config Lifecycle | 0 | 0 | 1 | 0 | [md](areas/secrets-lifecycle.md) · [html](areas/secrets-lifecycle.html) | llm_core URL-logging sinks log raw target_url without redact_url (preserves userinfo; admin-only logs). |
| **Total** | **0** | **2** | **7** | **3** | | |

---

## Systemic patterns

The repeated root causes below matter more than any single instance — a pattern that recurs across surfaces is a design gap, not a bug.

### 1. Untrusted content reaches the LLM unwrapped on multiple surfaces — and worse, re-promoted to the system role

**Root cause:** `prompt_security.untrusted_context_message` is the project's trust boundary for external text, but several flows either strip the wrapper or never apply it, and two flows then **re-emit** the result as a `role='system'` message that downstream turns treat as authoritative.

**Where it recurs:**
- prompt-injection — context compaction laundering (`src/context_compactor.py:336-417`); research 'Discuss' primer (`routes/research_routes.py:654-669`, `src/deep_research.py:609-700`); email→calendar auto-poller (`routes/email_pollers.py:513-611`).
- state — the *same* compaction code path also corrupts history structure (`src/context_compactor.py:336-456`).
- Adjacent unwrapped surfaces flagged as coverage gaps: MCP native `role='tool'` results (`agent_loop.py:1677-1683`), deep-research `_synthesize`/`_final_report` `role='user'` prompts.

**Systemic fix:** treat the untrusted wrapper as an invariant that survives every transform. Summaries/syntheses of untrusted content stay untrusted (emit as `role='user'`/wrapped, never bare `role='system'`); re-wrap tool and web results at every re-injection point; and gate any auto-applied side-effect (calendar delete/update) on the content's trust level, requiring confirmation for untrusted-derived ops.

### 2. Compaction mutates conversation history without preserving its structural invariants

**Root cause:** both auto and manual compaction rebuild history but break a structural invariant — either the leading-system **offset** (count taken from a preface+history payload, applied to a preface-less history) or **temporal ordering** (summary timestamped `now`, sinking past kept turns on reload).

**Where it recurs:**
- state — offset miscount drops/misorders turns (`src/context_compactor.py:336-456`).
- persistence — manual compaction reorders on reload (`routes/history_routes.py:584-642`).
- prompt-injection — the auto-compaction summarizer is the trust-laundering vector (same file).

**Systemic fix:** make compaction operate on explicit, validated message identities rather than positional offsets and wall-clock timestamps; assert post-conditions (no turn dropped, ordering preserved, roles unchanged) before persisting via `replace_messages`. One correct compaction primitive fixes the offset bug, the reorder bug, and removes the laundering surface.

### 3. Read-modify-write across an `await` with no claim/lock → lost updates & double-completion

**Root cause:** a row/file is read (or selected) before a long async gap (LLM call, SMTP send), then written/acted on as if nothing changed — no atomic claim, optimistic version, or lock spanning the await.

**Where it recurs:**
- persistence — memory audit snapshots `memory.json`, awaits a 30-120s LLM call, writes back the stale snapshot, clobbering concurrently-added same-owner rows (`services/memory/memory_extractor.py:508-639`).
- email — scheduled send delivers before flipping `status='sent'`, so a crash or second poller re-sends (`routes/email_pollers.py:1010-1085`).
- concurrency — singleflight owner never resolves its Future on CancelledError, poisoning a shared key (`src/task_scheduler.py:60-94`).

**Systemic fix:** claim-before-act. Acquire an atomic conditional UPDATE (`...WHERE status='pending'`) or per-key lock before the irreversible/long operation, and ensure the owner of any shared resolution always settles it in `finally` (covering CancelledError), not just `except Exception`.

### 4. Cancellation cleanup written as `except Exception`, missing `CancelledError`

**Root cause:** `asyncio.CancelledError` is (3.8+) a `BaseException`, so `except Exception` cleanup handlers silently skip it on Stop/disconnect — leaking subprocesses, exit stacks, and poisoning caches.

**Where it recurs:**
- concurrency — singleflight cache key poison (`src/task_scheduler.py:60-94`); orphaned tool subprocess (`src/agent_loop.py:3104-3133`); leaked MCP AsyncExitStack (`src/mcp_manager.py:325-378`).

**Systemic fix:** move resource/Future cleanup into `finally` (or `except BaseException`) and propagate cancellation to owned child tasks/subprocesses (`task.cancel()` + await) so a Stop tears down the whole subtree deterministically.

### 5. Naive datetime handling — local time stripped to naive instead of converted to UTC

**Root cause:** the store holds **naive-UTC** rows, but query windows are built from tz-aware **local** bounds and flattened with `.replace(tzinfo=None)`, yielding naive-LOCAL compared against naive-UTC.

**Where it recurs:**
- numeric-temporal — check-in calendar window misaligned by the owner's UTC offset (`src/task_scheduler.py:1205-1227`); related DST drift noted as a gap (`compute_next_run`).

**Systemic fix:** normalize to UTC via `astimezone(timezone.utc)` before stripping tzinfo (or keep everything tz-aware end-to-end); never use `.replace(tzinfo=None)` as a timezone conversion.

---

## Coverage map

### Areas inspected clean (no surviving findings)
- **Authentication, Authorization, Sessions & Tokens** — owner gates consistently enforce `effective_user`/`api_token_owner`.
- **Injection Sinks & SSRF** — JSON parsing throughout (no unsafe deserialization), no server-side template injection, outbound headers from fixed keys; SSRF validators present (DNS-rebinding TOCTOU accepted per threat model).
- **Networking, Streaming, Retry/Backoff, Timeouts** — shared client `http2=False`, lock-guarded cross-thread health/cache state.
- **Caching, Invalidation, RAG & Embeddings** — in-process dict + local file caches only; 1 candidate dropped as false positive.
- **Tool Parsing, Execution & MCP Subprocess Lifecycle** — admin/non-admin tool gating holds at the route layer.

### Untraced / aggregated coverage gaps
- **IDOR breadth:** full per-route audit of ~40 owner-scoped routers not exhaustive (authz); spot-checks all enforce owner scoping.
- **SSRF DNS-rebinding TOCTOU:** validated IP not pinned across all three validators — accepted under trusted-admin/private-network threat model (injection-ssrf).
- **Unwrapped LLM surfaces:** MCP `role='tool'` results and deep-research synthesis prompts not falsified end-to-end (prompt-injection).
- **Cancellation leaks:** not every task_scheduler executor branch / streaming generator `finally` traced (concurrency, networking).
- **Migrations & durability:** ~40 `init_db()` migrations not exhaustively verified; SQLite WAL/busy_timeout not confirmed (`database is locked` is an error, not corruption) (persistence).
- **DST / schedule validation:** `compute_next_run` DST path and `scheduled_day` range validation untraced; ≤ twice-yearly 1h drift, owner-only impact (numeric-temporal).
- **Email sinks:** `check_email_urgency` alert-send sink and `_send_smtp_message` partial-failure semantics not deeply traced; client-side `_sanitizeHtml` not fuzzed (email).
- **Secret-logging:** llm_core URL-logging sinks preserve userinfo (admin-only-readable logs) (secrets-lifecycle).
- **Runtime behavior:** all findings are static traces; nothing reproduced against a live model/DB/ChromaDB.

### Scope areas marked N/A (with reason)
- **Multi-tenant / cross-org isolation** — Odysseus is single-host with a trusted admin; user separation is best-effort owner-scoping, not a hard tenancy boundary (authz, state, persistence).
- **External OAuth/OIDC SSO trust boundary** — device flows are admin-gated provider logins, not end-user SSO (authz).
- **Unsafe deserialization / template injection / CRLF header injection** — none present; JSON throughout, fixed header keys (injection-ssrf).
- **Admin-intended powerful capabilities** — shell, file, email, MCP management, local model serving are by-design per `THREAT_MODEL.md` (prompt-injection, concurrency, persistence, tools-mcp, secrets-lifecycle).
- **Distributed / multi-process concerns** — no Redis/memcached, no multi-replica; single-process asyncio, so cross-node key collisions, distributed stampede, and cross-process file locking are N/A (caching, state, persistence, networking).
- **HTTP/2 multiplexing & cross-thread streaming races** — `http2=False`; generators run on the single event loop (networking).
- **Weak crypto / insecure-random tokens / timing side-channels** — `secrets.*` and `secrets.compare_digest`/bcrypt used; no hardcoded credentials (secrets-lifecycle).
- **Server-side stored-XSS from email HTML** — rendered only in-browser via client-side sanitizer; no server-side raw-HTML template (email).
- **Monetary float / integer-overflow numerics** — no currency arithmetic; Python arbitrary-precision ints (numeric-temporal).

---

*Generated by an automated multi-agent audit: parallel per-area finders → independent adversarial verification → per-area reports → this synthesis.*
