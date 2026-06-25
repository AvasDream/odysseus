# Numeric & Temporal Correctness, Scheduling — Audit Report

One owner-scoped check-in digest window is built in naive local wall-clock but compared against naive-UTC calendar rows, shifting buckets by the zone's UTC offset; the rest of the scheduling, RRULE, cron, monotonic-timeout and byte/GB-conversion paths inspected clean.

Critical: 0 | High: 0 | Medium: 0 | Low: 1; dropped false positives: 0

### [LOW] Assistant check-in calendar window strips timezone instead of converting to UTC, misaligning the query window by the local UTC offset

- **Severity:** Low — accuracy of a per-owner check-in summary is degraded; no cross-tenant leak (query is owner-scoped), so a correctness/UX defect rather than a privilege or data-exposure bug.
- **Confidence:** Confirmed by trace (verifier verdict: **uncertain** — verifier agent unavailable, treated as uncertain). Preconditions: a non-admin or admin owner sets a non-UTC timezone on their default-assistant CrewMember and runs a "...check-in" scheduled LLM task (is_checkin path); fires every time that task executes; triggerable by the task owner only.
- **Verification verdict:** UNCERTAIN — independent verifier could not be run; auditor trace is internally consistent but unconfirmed by a second pass.
- **Location:** `src/task_scheduler.py:1205-1227` (window build + strip); `src/task_scheduler.py:255-289` (`_digest_windows` / `_checkin_calendar_events`); re-print at `src/task_scheduler.py:1242`.
- **What is wrong (invariant):** When comparing datetimes against DB rows, both sides must be in the same reference frame. `CalendarEvent.dtstart` for timezone-carrying events is stored as naive UTC (`caldav_sync._to_utc_naive` and `calendar_routes._parse_dt_pair` convert tz-aware → UTC then strip tzinfo). The digest window boundaries are built from `now`, which when a task timezone is configured is tz-aware LOCAL time (line 1205: `_utcnow().replace(tzinfo=utc).astimezone(ZoneInfo(tz_name))`). Stripping tzinfo with `.replace(tzinfo=None)` (lines 1225-1226) yields naive LOCAL wall-clock, NOT naive UTC, so the window is offset from the stored UTC instants by the zone's UTC offset.
- **Why it matters:** For any owner whose `CrewMember.timezone` is a non-UTC zone, the "today/tomorrow", "this week" and "next_30_days" check-in buckets are shifted by up to +/-14h relative to actual stored UTC event times. Events near a bucket boundary are silently dropped from the digest or pulled into the wrong bucket; for zones behind UTC (the Americas) the early part of "today" is missed and late events of the prior day leak in. The event times re-printed via `ev.dtstart.strftime` (line 1242) are also raw UTC, compounding the misrepresentation.
- **Trigger:** A non-admin or admin owner sets a non-UTC timezone on their default-assistant CrewMember and runs a "...check-in" scheduled LLM task (is_checkin path). Fires every time that task executes. Triggerable by the task owner only.
- **Fix direction:** Convert the window bounds to UTC before stripping: `_s = start.astimezone(timezone.utc).replace(tzinfo=None) if start.tzinfo else start` (and same for `_e`), instead of dropping the offset. Equivalently, build `_digest_windows` from a naive-UTC `now` for the DB query while keeping the tz-aware `now` only for the human-readable `time_str`.
- **Root cause tag:** temporal

```
now = _utcnow().replace(tzinfo=timezone.utc).astimezone(ZoneInfo(tz_name))  # tz-aware LOCAL
...
for label, start, end in _digest_windows(now):
    _s = start.replace(tzinfo=None) if start.tzinfo else start   # strips offset -> naive LOCAL, not UTC
    _e = end.replace(tzinfo=None) if end.tzinfo else end
    evs = _checkin_calendar_events(_db, task.owner, _s, _e)  # compares against naive-UTC dtstart
```

## Coverage

### Sub-areas inspected clean
- `compute_next_run`: HH:MM parse fails closed on malformed input (out-of-range/non-numeric → None); daily/weekly/monthly candidate math advances forward; monthly short-month clamps to last day correctly; cron path delegates to croniter and converts tz-aware → naive UTC consistently; "once" returns None after the scheduled_date passes so completed tasks do not re-fire.
- Missed-while-down handling: `start()` marks zombie running/queued runs aborted and pushes overdue next_run forward 60s, then post-run `compute_next_run` recomputes forward from now — no catch-up storm / no repeated same-tick dispatch.
- `_shared_cache` TTL uses `time.monotonic()` (correct monotonic-for-timeout usage); singleflight future set/clear paths release the pending entry on both success and exception.
- `_loop` sleep computation clamps delta to `max(1.0, min(60.0, delta))` so a past/negative next_run yields 1s, not a negative or zero sleep.
- RRULE expansion (`_expand_rrule`): naive/naive comparisons are consistent; `UNTIL=...Z` is stripped when DTSTART is naive to avoid dateutil tz-mix crash; `_RRULE_EXPANSION_LIMIT=1000` caps unbounded expansion; overlap filter uses correct half-open `[start,end)` semantics; malformed RRULE falls back to a single overlap-checked event.
- `fit.py` scoring: `_fit_score` guards `available<=0` and `required>available`; `_speed_score`/`_context_score` targets are never zero; `estimate_memory_gb` and `params_b` guard `pb<=0` / malformed counts; `gpu_count` coerced via `or 1` before division.
- `hardware.py`: all byte→GB conversions guard non-numeric (isdigit/try-except) and zero (`total_gb<=0` → return None); vram parsing tolerates `[N/A]` unified-memory devices; cache TTL uses `time.time()` for a 24h wall-clock cache (acceptable, not a timeout).
- `caldav_sync`: `_to_utc_naive` converts tz-aware → UTC before stripping; all-day widened to midnight datetime; prune gated on a clean parse so partial reads never delete upstream-present events; SSRF host validation + redirect pinning intact.
- `email_thread_parser`: 200KB input cap and `[:1500]` meta truncation bound all regex work; attribution/header regexes use MULTILINE without nested unbounded quantifiers, so no catastrophic-backtracking ReDoS on untrusted email bodies.

### Coverage gaps
- DST transition correctness in `compute_next_run`'s tz path was not exhaustively traced: `now.replace(hour=h,minute=m)` keeps the pre-resolved offset and may drift ~1h across spring-forward/fall-back boundaries, but this is at most a twice-yearly 1h schedule drift and likely accepted; not reported.
- `scheduled_day` is not range-validated at the create route (`task_routes.py`); weekly with `scheduled_day>6` schedules an off-weekday run and monthly with 0/>31 clamps to month-end — confirmed as owner-only schedule mis-timing with no privilege/security impact, so noted but not reported.
- The caldav lib's internal handling of naive datetimes passed to `date_search` (start/end) was not traced into the library; assumed the lib treats them as UTC consistent with the stored naive-UTC rows.

### Assumptions made
- `CalendarEvent.dtstart` for timezone-carrying (is_utc=True) events is stored as naive UTC — confirmed in `caldav_sync._to_utc_naive` and `calendar_routes._parse_dt_pair`; UI events created without explicit offset are naive-local (is_utc=False), making the DB a mix, which the check-in query treats uniformly.
- croniter and dateutil.rrule behave per their documented contracts.
- `task_scheduler` runs single-threaded on the asyncio loop except for `asyncio.to_thread` CalDAV sync; DB sessions are per-call `SessionLocal()` so cross-coroutine shared mutable state is limited to `_executing` (lock-guarded) and `_shared_cache` (lock-guarded).

### N/A scope areas
- hwfit `fit.py` / `hardware.py` model-ranking numerics are admin/UI-facing read-only scoring over a trusted local catalog; miscalculated tok/s or fit scores carry no security impact — out of security scope.
- Float == comparison on money: no monetary/currency arithmetic exists in the assigned files, so the float-equality-on-money class is N/A here.
- Integer overflow: Python ints are arbitrary precision; no fixed-width integer sinks were reached on the traced paths, so true integer overflow is N/A.

### Candidates dropped as false positives
0
