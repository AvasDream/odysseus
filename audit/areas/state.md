# In-Memory State Management & Invariants

Audit of conversation/message-list integrity, derived-state synchronization, shared-reference aliasing, illegal state transitions, and singleton/global mutation safety in the Odysseus codebase.

Critical: 0 | High: 1 | Medium: 0 | Low: 0; dropped false positives: 0

### [HIGH] Compaction persists corrupted history: preface system-message count is applied as an offset into session.history (which has no preface), dropping and misordering real conversation turns

- **Severity:** High — silent, permanent loss of conversation messages plus role/ordering corruption on every auto-compaction (data-integrity, not security).
- **Confidence:** Confirmed by trace. Preconditions: any session owner (admin or non-admin) using normal chat or agent mode (both route through `build_chat_context -> maybe_compact` at `chat_helpers.py:716`); estimated tokens cross `COMPACT_THRESHOLD = 0.85` of the model context window with >=4 conversation messages, and the summarization LLM call succeeds. No untrusted input or special privilege required; reproduces deterministically on the first auto-compaction.
- **Verification verdict:** real (skeptic re-traced the path; corrected severity retained at High).
- **Location:** `src/context_compactor.py:336-342,402,409,420-456`; `routes/chat_helpers.py:693,716`; `src/prompt_security.py:60-82,201-204`
- **What is wrong (invariant):** `session.history` must contain exactly the persisted conversation; after compaction the persisted history must equal (leading-system-messages-of-history) + summary + (recent conversation), with NO conversation message both un-summarized and un-kept. The code instead treats `system_msg_count` (a count of system messages in the per-turn `preface + history` payload) as the number of LEADING system messages in `session.history`. But the preface system messages (UNTRUSTED_CONTEXT_POLICY and the optional preset system prompt) are built per-turn and are NEVER stored in `session.history`, so `system_msg_count` overcounts history's leading system messages by the number of preface system messages (>=1 always).
- **Why it matters:** On every auto-compaction the persisted (and reloaded-next-turn) history is corrupted: the first `system_msg_count` REAL messages (user/assistant turns) are mislabeled as a system prefix and kept verbatim at the top; `recent_history = session.history[system_msg_count + split_point:]` is shifted forward so `system_msg_count` recent conversation messages are silently DROPPED (neither summarized nor kept); and role ordering breaks (a user turn lands where the summary system message should anchor context). The in-memory result used for THIS turn is correct (returned `compacted`), so the damage is invisible until the next turn reloads the mangled history via `replace_messages -> get_context_messages`. The loss is permanent and can also produce orphaned tool/tool_calls pairings on reload.
- **Trigger (who):** Any session owner simply chatting until estimated tokens cross COMPACT_THRESHOLD (85%) with >=4 convo messages. Fires for both chat and agent modes. UNTRUSTED_CONTEXT_POLICY is appended to preface unconditionally (`chat_processor build_context_preface` lines 201-204), so `system_msg_count` is >=1 on every compaction — at least one recent message is dropped every time; with a preset system prompt or a research-spinoff primer it drops 2-3.
- **Fix direction:** Do not derive the history offset from the count of system messages in the per-turn payload. In `_update_session_history`, compute the leading-system run of `session.history` itself (count `ChatMessage`s with `role=='system'` from index 0 until the first non-system) and use that as both the `system_prefix` length and the base for `effective_split`; or pass that history-local count from `maybe_compact` instead of `len(system_msgs)`.
- **Root cause tag:** `state-invariant`

```text
routes/chat_helpers.py:693  messages = preface + sess.get_context_messages()
                            (preface = per-turn system/user context, NOT persisted to history)
chat_processor.py:201-204   appends {role:system, UNTRUSTED_CONTEXT_POLICY} to preface every turn
context_compactor.py:336-342  for msg in messages: if role=='system': system_msgs.append(msg)
                              -> counts preface system msgs too (>=1)
context_compactor.py:409    _update_session_history(session, split_point, summary,
                                                    system_msg_count=len(system_msgs))
context_compactor.py:434-447
    effective_split = system_msg_count + split_point
    system_prefix   = list(session.history[:system_msg_count])
    recent_history  = session.history[effective_split:]
    new_history     = system_prefix + [summary_msg] + recent_history
    -> session.history has NO leading preface system messages, so system_msg_count>=1
       slices real user/assistant turns into system_prefix and shifts recent_history
       forward, dropping session.history[split_point : split_point + system_msg_count].

Concrete trace:
  history = [U1,A1,U2,A2,U3,A3,U4], preface = [SYS_policy]
  system_msgs = 1, convo_msgs = 7, split_point = 3
  compacted (sent THIS turn) = [SYS, summary, A2,U3,A3,U4]   <- correct
  _update_session_history(split_point=3, system_msg_count=1):
    effective_split = 4
    system_prefix   = history[:1] = [U1]   (USER turn mislabeled as system prefix,
                                            kept verbatim at top AND already summarized)
    recent_history  = history[4:] = [U3,A3,U4]
    -> A2 (index 3) is silently DROPPED (in recent so not summarized; below slice so not kept)
    new_history     = [U1, summary, U3, A3, U4]
  Exactly system_msg_count (>=1; 2 with a preset prompt) recent messages lost per compaction,
  plus a role/ordering break.

Persistence: _update_session_history -> manager.replace_messages
  (core/session_manager.py:309-349) DELETEs all DB messages for the session and re-inserts
  the corrupted history, overwriting in-memory session.history. Loss is permanent and reused
  on the next turn; invisible on the triggering turn.
```

## Coverage

**Sub-areas inspected clean:**
- `core/session_manager.py` `add_message`/`_persist_message`/`truncate_messages`/`replace_messages`: `message_count` derivation and in-memory/DB sync are consistent; `replace_messages` reorders deterministically via microsecond-offset timestamps; deleted-session callback fails closed (drops cached session).
- `core/models.Session`: per-instance history list created in `__post_init__` (no shared dataclass default); `_history` is a property aliasing `history` (no divergence). `get_context_messages()` builds fresh dicts via `to_dict`; list-level aliasing of `session.history` is avoided in `build_chat_context` via `preface + ...`.
- `src/agent_loop.py` message mutation: system-prompt insertion (1422), merge of consecutive system messages (1424-1436), and `_append_round_history` append paths operate on the freshly-built `messages` list and fresh dicts, not on `session.history` ChatMessage objects; reasoning_content stripping mutates only loop-local dicts.
- `src/model_context.py` `_context_cache` keyed on `(endpoint_url, model)`; local endpoints bypass cache and re-query; known-flag is bound to the value it proves in `budget_context_for_model` — no stale-flag/value pairing.
- `src/settings.py` `load_settings` TTL cache: callers in `admin_tools` mutate the returned dict then immediately `save_settings` (which invalidates cache), so the brief in-place mutation does not outlive the save; structured-default reset aliases `DEFAULT_SETTINGS[key]` but is serialized to JSON on save (no lasting shared-reference mutation).

**Coverage gaps:**
- Did not exhaustively trace every stream-cancellation / client-disconnect path in `agent_loop.py` (3484 lines) for partial-history persistence when a turn aborts mid-round; the assistant message is added at end-of-turn in `chat_routes`, but interrupted-turn `add_message` calls (lines 1242/1388 'stopped' paths) were not fully reconciled against the compaction state.
- Group-chat / compare-mode concurrent turns on the same `session_id` (multiple `stream_agent_loop` generators sharing one cached Session in `self.sessions`) were not stepped through for interleaved history appends; asyncio single-thread limits but await points between read of `session.history` and `replace_messages` could interleave across two in-flight requests for the same session.

**Assumptions made:**
- `build_chat_context` (`routes/chat_helpers.py:693`) is the canonical message-assembly path for both `/chat` and `/chat_stream` and the only feeder of `maybe_compact` in production chat (verified call sites at `chat_routes.py:396,663`).
- Preface system messages (preset prompt, UNTRUSTED_CONTEXT_POLICY) are never persisted into `session.history` — confirmed by `add_user_message`/`add_assistant_message` only writing role user/assistant, and preface being rebuilt each turn and discarded.
- `estimate_tokens`-based COMPACT_THRESHOLD gate is reachable in normal use (long conversations on default ~128K or smaller local context windows).

**N/A scope areas:**
- Multi-host/multi-process shared-memory concerns: Odysseus is single-host single-process (asyncio), so module globals are not cross-process shared.
- "Admin can perform powerful action" state changes (settings writes via `admin_tools`, shell, MCP) are by-design per THREAT_MODEL.md and excluded.

**Candidates dropped as false positives:** 0
