# Persistence, Transactions, Durability & Migrations — Audit

Two confirmed durability/correctness defects: a lost-update race when the memory audit writes back a stale snapshot across an LLM await, and a compaction timestamp ordering bug that reorders the conversation on DB reload. No security/priv-esc issues found; atomic_io, ALTER-TABLE/encrypt migrations, prefs RMW, and session-manager transactions inspected clean.

Critical: 0 | High: 0 | Medium: 2 | Low: 0; dropped false positives: 0

---

### [MEDIUM] Memory audit silently drops memories added during its LLM window (lost update across await)

- **Severity:** Medium — silent, permanent loss of the owner's own freshly-added memory entry with no error surfaced; limited to own non-critical advisory data and recoverable by re-adding, so not High.
- **Confidence:** Confirmed by trace. Preconditions: any authenticated non-admin with `can_manage_memory` triggers an audit that actually invokes the LLM (store changed since last tidy so the fingerprint short-circuit does not fire, >=1 entry exists); during the 30-120s await the same owner completes a full read-modify-write that adds a same-owner entry (POST /api/memory/add, a background `extract_and_store` save from another session, an import, or a second concurrent audit).
- **Verification verdict:** real (re-traced against current source; no lock, single-flight guard, threat-model acceptance, or framework default prevents it).
- **Location:** `services/memory/memory_extractor.py:508-639` (audit), `:463` (extract save); `routes/memory_routes.py:119-121,272-306` (manual trigger / add); store has no lock in `src/memory.py:35-213`.
- **What is wrong (invariant):** Read-modify-write on the single shared `memory.json` store must not lose concurrent writes. `audit_memories` snapshots the store at line 508, runs a 30-120s LLM call (a real asyncio yield point), then rebuilds the saved set from that STALE snapshot plus a re-read that only rescues OTHER owners' rows (line 631) and None-owner legacy rows. A same-owner row created during the window is in neither set, and the whole file is overwritten at line 639. There is no lock and no merge of same-owner rows created during the LLM window.
- **Why it matters:** Any memory created for the same owner during the audit's LLM call is silently and permanently clobbered: a background auto-extraction save (line 463), a manual POST /api/memory/add (line 121), an import, or a second concurrent audit. Own-data loss, no error surfaced.
- **Trigger / who:** Any authenticated non-admin triggers POST /api/memory/audit on their own store (or an auto-extraction inline-audit fires); while that LLM call runs, the same owner adds a memory via API, sends another chat turn whose background extraction saves a new fact, imports a backup, or a second audit overlaps. The 30-120s window makes the interleave easy to hit; the per-session sequential extraction queue does NOT serialize across different sessions of the same owner nor across a manual audit running alongside a background extraction.
- **Fix direction:** Serialize memory-store mutations with a per-owner `asyncio.Lock` held across load+modify+save, OR have `audit_memories` re-read the store after the LLM call and union in any same-owner rows whose id is not in the audited set before writing (treat them as new, keep them).
- **Root cause tag:** race

```text
508: existing = memory_manager.load(owner=owner)   # pre-LLM snapshot
542: await llm_call_async(..., timeout=120)         # real yield point, up to 120s
589: final_entries derived from `originals` (stale line-508 snapshot)
628: if owner:
629:     all_entries = memory_manager.load_all()     # re-read
631:     other_entries = [e for e in all_entries
                          if e.get('owner') != owner and e.get('owner') is not None]
633-635: legacy-rescue loop keeps only owner is None rows
636: saved_entries = final_entries + other_entries   # same-owner rows added during window in NEITHER set
639: memory_manager.save(saved_entries)              # overwrites whole file, dropping them

MemoryManager (src/memory.py:35-213): load/load_all/save/add_entry are plain sync file I/O.
save() uses os.replace for tear-free writes only — does NOT prevent a lost update across RMW.
No asyncio.Lock / single-flight guard anywhere around audit_memories or extract_and_store.
```

---

### [MEDIUM] Manual compaction reorders the conversation on reload (summary sinks to the end)

- **Severity:** Medium — durability/correctness impact: corrupts the persisted transcript and the context the model sees after reload. From a pure security standpoint this would be Low/none (no auth/priv-esc/injection).
- **Confidence:** Confirmed by trace. Preconditions: an authenticated session owner calls POST /api/session/{id}/compact on a session with >=6 messages and the LLM summary call succeeds; the defect is latent until the session is re-hydrated from the DB (process restart, in-memory cache eviction, or any path through `_load_session_from_db` / `_db_to_session`). In-memory order is correct until then, masking it in normal single-process testing.
- **Verification verdict:** real (both hydration paths — timestamp-ordered query and the no-`order_by` relationship path — reproduce the wrong order; confirmed no re-sort after hydration).
- **Location:** `routes/history_routes.py:584-642`; reload ordering `core/session_manager.py:132-133,144-146`; relationship without order_by `core/database.py:154`.
- **What is wrong (invariant):** The persisted (DB) message order must match the intended in-memory order so a reload reproduces the same conversation. `compact` builds in-memory history as `[system_summary, summary_msg] + recent` (line 597), but persists the two summary rows with `timestamp=now` (lines 617-635) while the kept recent rows retain their ORIGINAL earlier timestamps. DB reload orders strictly by timestamp (or by insertion/rowid order on the relationship path), placing the later-stamped summaries last.
- **Why it matters:** After re-hydration, the compaction summary and its hidden `[Conversation summary]` system-context message appear AFTER the recent messages instead of before them, corrupting conversation order and the context the model sees; the visible 'Conversation compacted' note also jumps to the tail.
- **Trigger / who:** Any authenticated session owner calls POST /api/session/{id}/compact on a session with >=6 messages, then the session is reloaded from the DB (e.g. after a restart or cache eviction). No special privileges or untrusted content required.
- **Fix direction:** Timestamp the inserted summary rows BEFORE the kept recent rows (e.g. `now = min(recent timestamps) - delta`), or re-stamp the kept recent rows to follow the summaries, so DB timestamp/insertion order matches the intended `[summaries..., recent...]` order.
- **Root cause tag:** temporal

```text
597: new_history = [system_summary, summary_msg] + list(recent)   # summaries FIRST (correct intent)
610: for m in db_msgs[:-keep_count]: db.delete(m)   # kept rows keep original (earlier) timestamps
617: now = datetime.now(timezone.utc)
618-625: db_sys_summary = DbChatMessage(..., timestamp=now)   # LATER than every kept row
627-635: db_summary    = DbChatMessage(..., timestamp=now)

Reload (_db_to_session) reproduces wrong order on BOTH paths:
 (a) order_by(DbChatMessage.timestamp)  -> earlier recent rows first, summaries last
 (b) db_session.messages relationship (core/database.py:154, no order_by)
     -> SQLite returns rowid/insertion order; summaries inserted AFTER recent rows -> last
No re-sort after hydration: _db_to_session returns history as-built;
Session.get_context_messages preserves order (only filters metadata.source=='slash').
```

## Coverage

### Sub-areas inspected clean
- `core/atomic_io.py`: `atomic_write_json/atomic_write_text` correctly write tmp+fsync+os.replace; PID-suffixed tmp avoids cross-process collision.
- `core/database.py` ALTER-TABLE migrations: each guards with `PRAGMA table_info` before adding columns; `CREATE INDEX IF NOT EXISTS` used — idempotent and safe to re-run.
- `core/database.py` encrypt-legacy migrations (`_migrate_encrypt_endpoint_keys/_signatures/_email_passwords`): use raw SQL to bypass the `EncryptedText` decorator and guard with `is_encrypted()` — no double-encryption, idempotent.
- `src/caldav_sync.py` `_sync_blocking`: prune correctly gated (skips on parse_failed, only within window, only origin=='caldav' with remote_href and no pending writeback, excludes seen_uids); per-calendar try/except with rollback; runs in its own to_thread SessionLocal.
- `routes/prefs_routes.py` `_save_for_user`: load+modify+save has no await between read and write, so concurrent async handlers serialize on the single-threaded loop — no last-write-wins clobber; multi-user `_users` slot preserved when auth disabled.
- `core/session_manager.py` `truncate_messages/replace_messages/delete_session`: DB ops committed atomically within one transaction with matching in-memory updates; `delete_session` detaches documents to avoid orphan FK before deleting session.
- `services/memory/memory.py` and `skills.py` saves: write tmp then os.replace; not invoked via to_thread so the fixed-name tmp does not cause cross-thread collision.

### Coverage gaps
- Did not exhaustively trace every one of the ~40 migrations in `init_db()` for column-default backfill correctness (e.g. `_migrate_assign_legacy_owner`, `_migrate_backfill_document_owner_from_session`); spot-checked the encrypt and add-column ones.
- Did not verify SQLite is run with WAL/busy_timeout; default rollback-journal mode plus `check_same_thread=False` can surface 'database is locked' under concurrent writers, but that degrades to an error rather than corruption and is largely threat-model-accepted.
- caldav writeback path (`src/caldav_writeback.py`) not fully traced for partial-failure rollback of `sync_pending` flags.
- Did not trace whether two concurrent `sync_caldav(owner)` calls (scheduled + manual) collide on the uid UNIQUE constraint beyond confirming the per-calendar except/rollback would catch the IntegrityError (degrades to a failed sync, not corruption).

### Assumptions made
- asyncio event loop is single-threaded; a coroutine block with no await between a load and a save is atomic with respect to other coroutines (used for prefs clear and `extract_and_store`'s own RMW).
- `memory_vector.find_similar/add/rebuild` and `memory_manager.load/save` are synchronous (no internal run_in_executor/to_thread); confirmed by absence of to_thread/run_in_executor in memory.py, memory_extractor.py, memory_routes.py.
- DB message reload always orders by `DbChatMessage.timestamp` (confirmed in `_db_to_session` and history get fallback), so persisted timestamp ordering determines reloaded conversation order.
- POSIX `os.replace` is atomic on the same filesystem.

### N/A scope areas
- Cross-process file locking / multi-replica concurrency: Odysseus is single-host single-process, so the only concurrency is asyncio tasks + a few to_thread workers — distributed-write concerns N/A.
- Admin-wipe raw `open('w')` on memory.json (`admin_wipe_routes.py:48-49`) writes an empty list; a crash mid-write yields an empty/truncated file which equals the intended wiped state — not a real durability defect, and admin-only by design.

### Candidates dropped as false positives
0
