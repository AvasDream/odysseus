# Email Subsystem: IMAP/SMTP, Parsing & Pollers — Audit

Untrusted email content reaching sinks, IMAP/SMTP lifecycle, poller dedup/state, MIME parsing, attachment path handling, and cross-tenant IDOR on message/account IDs.

Critical: 0 | High: 0 | Medium: 1 | Low: 0; dropped false positives: 1

---

### [MEDIUM] Scheduled email is delivered before the row is claimed/marked sent — crash or dual-driver causes duplicate send

- **Severity:** Medium — at-most-once delivery invariant is violated by normal operational events; impact bounded to duplicate delivery of an email the owner already intended to send.
- **Confidence:** Confirmed by trace. Preconditions: a scheduled email exists in `scheduled_emails` with `status='pending'` and `send_at <= now` (created via POST /api/email/schedule or agent-approved send). Then EITHER (A) the server is killed/restarted during the SMTP round-trip — after `_send_smtp_message` returns (1057) but before the `UPDATE` at 1070 commits — under default config (`ODYSSEUS_INPROCESS_POLLERS` unset/on); on the next poller tick the still-pending row is re-delivered. OR (B) an operator runs both the in-process poller and a cron/systemd `odysseus-mail poll-scheduled`, and both passes overlap on the same due row before either commits `status='sent'`. No attacker required.
- **Verification verdict:** real (severity confirmed Medium). The skeptic re-traced the source: candidate rows are SELECTed with `WHERE status='pending' AND send_at <= ?` (1010-1014), the connection is closed (1015) before delivery begins, the irreversible SMTP send is at 1057, and the status flip happens only after success at 1070. No claiming UPDATE, lock, BEGIN IMMEDIATE, in-loop re-check, or receiver-side dedup exists anywhere; the `X-Odysseus-Ref` header (1040) is informational only. Finding survived falsification.
- **Location:** routes/email_pollers.py:1010-1085 (`_scheduled_poll_once`); driver 1088-1101
- **What is wrong (invariant):** A queued scheduled email must be delivered at-most-once: the row must be atomically claimed (status flipped out of `pending`) BEFORE the irreversible SMTP send, so re-entry can never re-deliver it. Here the claim (UPDATE status='sent', 1070) happens AFTER `_send_smtp_message` succeeds (1057), and the initial SELECT (1010-1014) does not claim the rows.
- **Why it matters:** The same email is sent twice (or N times) to all To/Cc/Bcc recipients. Trigger (a): the process is killed/restarted in the window between SMTP delivery (1057) and the status UPDATE (1070) — on restart the row is still `pending` and due, so it is re-selected and re-delivered. Trigger (b): two drivers run concurrently (in-process poller + cron `odysseus-mail poll-scheduled`) — both SELECT the same pending row and both deliver before either flips status. The docstring (1122-1123) acknowledges (b) as a footgun but relies on an env flag rather than an atomic claim.
- **Trigger / who:** No attacker needed; normal operational events (deploy, OOM, crash, SIGKILL) or operator misconfiguration. Affects any owner with scheduled/agent-approved sends. (A) requires no misconfiguration; (B) requires the dual-driver setup.
- **Fix direction:** Atomically claim before sending: `UPDATE scheduled_emails SET status='sending' WHERE id=? AND status='pending'` and proceed only if rowcount==1; on success set `sent`, on failure set `failed`/`pending` with a bounded retry. This makes re-entry idempotent and closes both the crash window and the dual-driver race.
- **Root cause tag:** double-completion

```text
# routes/email_pollers.py
rows = conn.execute(f"""SELECT id, ... FROM scheduled_emails
        WHERE status = 'pending' AND send_at <= ?""", (now_iso,)).fetchall()  # 1010-1014
conn.close()                                                                   # 1015 (no lock/txn spans read->write)
...
_send_smtp_message(cfg, cfg["from_address"], recipients, outer.as_string())    # 1057 (irreversible)
...
conn2.execute("UPDATE scheduled_emails SET status='sent' WHERE id=?", (sid,))  # 1070 (claim happens only AFTER send)

# scripts/odysseus-mail cmd_poll_scheduled (line 267) invokes the SAME _scheduled_poll_once()
# in-process poller runs it via asyncio.to_thread (1098); both can select the same due row.
```

---

## Coverage

### Sub-areas inspected clean
- **SMTP header injection:** subject/to/cc set as MIME headers (email_routes.py:2483-2493) but compat32 Generator raises `HeaderParseError` on embedded newlines at `as_string()`/`as_bytes()` (verified empirically), so CRLF fails the send rather than injecting headers. `_decode_header` CRLF strings hit the same guard.
- **IDOR on account_id:** `require_owner` resolves account_id and calls `_assert_owns_account` (email_helpers.py:307-316); all body/path routes (/send, /draft, /schedule, /summarize, /accounts/{id}, set-default, oauth authorize, reminders) call `_assert_owns_account` explicitly. `_get_email_config` nullifies cross-owner rows (787-788).
- **IMAP connection pool:** keyed by (account_id, owner) (email_routes.py:575,606) — no cross-tenant reuse; failed AUTHENTICATE shuts the socket (email_helpers.py:952-962); `_imap` context manager releases on every path incl. exception (998-1011).
- **Agent loopback privilege:** email tools loopback via `_internal_headers` with `X-Odysseus-Owner` = trusted SESSION owner; app.py:338-343 only honors it for an existing user and the route still runs `_assert_owns_account`.
- **Untrusted email -> agent context (main chat):** active-email body_preview wrapped via `untrusted_context_message` (agent_loop.py:1240); all tool results incl. read_email bodies wrapped (1696-1697). No system-role injection found.
- **Calendar extraction from untrusted email (poller):** ops run via `do_manage_calendar(owner=_acct_owner)`; event queries owner-scoped (tool_implementations.py:921-925); EXISTING_EVENTS owner-scoped (email_pollers.py:510). Malicious email cannot touch another tenant's events.
- **Attachment filename path handling:** `_extract_attachment_to_disk` sanitizes via regex (email_helpers.py:1315) stripping `/` and `\`; `attachment_extract_dir` flattens folder/uid and asserts containment (505-516); `attachment_as_doc` adds a commonpath check (email_routes.py:1648-1656). No traversal reachable.
- **IMAP SEARCH injection:** search rejects CRLF in q (email_routes.py:1205) and escapes backslash/quote (1232-1233); `_q()` quotes mailbox names.
- **Google OAuth:** state is HMAC-signed (account_id+owner+nonce) and callback rechecks `row.owner == state owner` (email_routes.py:3661-3663). CSRF/confused-deputy mitigated.
- **HTML sanitization:** outbound WYSIWYG HTML allowlist-sanitized server-side (`_sanitize_email_html`, email_routes.py:517); inbound HTML DOM-sanitized client-side via `_sanitizeHtml` (static/js/emailLibrary/utils.js:158-219) before innerHTML.

### Coverage gaps
- `check_email_urgency` scheduled task (the active urgency path; in-poller block at email_pollers.py:715-841 is dead because `auto_urgent=False`) not fully traced to its alert-send sink — subject/body construction and any header-injection there not exhaustively verified.
- MCP email tool name->account_id resolution layer (`mcp__email__*`) inferred to flow through owner-scoped routes but the exact label->account_id resolver not located/read; still blocked at the route by `_assert_owns_account`, but the resolver itself was not line-traced.
- `_send_smtp_message` partial-failure semantics (per-recipient SMTP rejections, RSET, multi-RCPT) at email_helpers.py:153 not deeply traced.
- Frontend render path injecting parse_thread turns/body_html via innerHTML confirmed to route through `_sanitizeHtml`, but completeness of that denylist sanitizer against mutation XSS / namespace confusion not exhaustively fuzzed.

### Assumptions made
- stdlib email uses default compat32 policy here (no `policy=` override), so `Generator.as_string()`/`as_bytes()` raises `HeaderParseError` on header values with embedded newlines — verified empirically.
- imaplib rejects CRLF inside command arguments, so folder/uid/search CRLF cannot inject extra IMAP commands.
- Each authenticated multi-user deployment assigns every user a non-empty `owner`; `owner==''` denotes unconfigured single-user mode where cross-tenant concerns are vacuous.
- uuid4 tokens for compose uploads are unguessable.
- `_load_or_create_key()` returns a stable per-deployment secret so HMAC-signed OAuth state cannot be forged.

### N/A scope areas
- Webhook SSRF, MCP subprocess management, local model serving, vault, 2FA, shell exec — outside email subsystem scope.
- Inbound HTML stored-XSS as a server-side sink: HTML rendered only in-browser via client-side `_sanitizeHtml`; no server-side template emits raw email HTML — server-side stored-XSS is N/A.
- Cross-account connection reuse leaking creds: pool key includes account_id and owner — N/A.

### Candidates dropped as false positives: 1
- **email_boundaries thread-cache not owner-scoped** (Low, claimed) — DROPPED. Structural asymmetry is real (`email_boundaries` PK is `message_id` alone, no owner_clause on the read at email_routes.py:1407-1410, unlike its owner-scoped siblings), but the leak cannot fire: NO WRITER EXISTS. The sole former writer `mark_email_boundaries` is retired (src/task_scheduler.py:248-252), its handler is deleted, and retired tasks are purged. `turns_json` is always NULL and the read falls through to a fresh `parse_thread` on the user's own body. Latent hardening observation only; not a triggerable vulnerability.
