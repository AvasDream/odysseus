# Concurrency, Async Safety, Races & Cancellation

Cancellation-safety gaps in singleflight caching, agent tool execution, and MCP connect leave shared state poisoned or external resources (subprocesses, HTTP transports) leaked because `except Exception` does not catch `asyncio.CancelledError`.

Critical: 0 | High: 0 | Medium: 1 | Low: 2; dropped false positives: 0

### [MEDIUM] CancelledError in `_cached()` owner leaks an unresolved pending future, permanently poisoning the shared singleflight cache key

- **Severity:** Medium — durable (process-lifetime) cross-user availability loss of shared scheduled-task fetches, triggerable by a non-admin.
- **Confidence:** Confirmed by trace. Preconditions: two or more users have check-in/digest tasks touching the same shared integration (same Miniflux `base_url`, or same MCP server snapshot tool); one user's task is the singleflight owner suspended inside `_cached` at `await fetch()` (httpx GET, up to ~10s, or `mcp.call_tool`) or at the line-85 lock acquisition; that task is cancelled (most directly via the owning non-admin user's `POST /tasks/{task_id}/stop`). No special privilege required beyond owning one task that shares a global cache key.
- **Verification verdict:** real (severity Medium confirmed). Re-traced end-to-end: cleanup gap, lost wakeup, cancel delivery, cross-user blast radius, and non-admin reachability all confirmed; all falsification attempts failed.
- **Location:** `src/task_scheduler.py:60-94` (owner path 83-94); callers `src/task_scheduler.py:1302, 1339`; cancel source `src/task_scheduler.py:2089-2102`.
- **What is wrong (invariant):** The owner of an in-flight singleflight key must ALWAYS remove `_shared_cache_pending[key]` and resolve (set_result/set_exception/cancel) the future before exiting, on every path. The `except` clause only catches `Exception`, so `asyncio.CancelledError` (a `BaseException`) bypasses cleanup.
- **Why it matters:** If the owner is cancelled while suspended at `await fetch()` (line 84) or the success-path lock (line 85), neither lines 87/88 nor 92/93 run. `_shared_cache_pending[key]` keeps an unresolved Future and the cache entry is never written. (1) Every concurrent waiter at `await pending` (line 82) hangs forever (lost wakeup). (2) Every future caller for that key hits lines 71-74, finds the stale pending future, awaits it, and also hangs forever. Keys are process-global and shared across users (e.g. `("miniflux_unread", base_url)`, `("mcp_snapshot", qualified, args)`), so one user stopping their own task can hang other users' scheduled tasks touching the same key, until process restart.
- **Trigger:** A scheduled/action check-in or digest task (`_fetch_miniflux` at :1302 or `_call_mcp` MCP snapshot at :1339) becomes the singleflight owner and suspends inside `await fetch()`. The owning (non-admin) user clicks Stop -> `stop_task()` -> `handle.cancel()` (`task_scheduler.py:2093`) delivers CancelledError at that await; cleanup is skipped; the key is poisoned for everyone. Triggerable by any non-admin task owner.
- **Fix direction:** Wrap the owner body in `try/except BaseException` or a `finally` that always pops `_shared_cache_pending[key]` and, if the future is not yet done, calls `pending.cancel()` (or `set_exception`) so waiters wake; re-raise CancelledError. E.g. `finally: _shared_cache_pending.pop(key, None); if not pending.done(): pending.cancel()`.
- **Root cause tag:** lost-wakeup

```
83  try:
84      val = await fetch()
85      async with _shared_cache_lock:
86          _shared_cache[key] = (time.monotonic() + ttl, val)
87          _shared_cache_pending.pop(key, None)
88      pending.set_result(val)
89      return val
90  except Exception as e:   # CancelledError (BaseException) NOT caught
91      async with _shared_cache_lock:
92          _shared_cache_pending.pop(key, None)
93      pending.set_exception(e)
94      raise
--- waiter path ---
81  if not owner:
82      return await pending   # hangs forever if owner cancelled
--- stop trigger ---
2093  if handle and not handle.done():
2094      handle.cancel()
```

### [LOW] Orphaned tool-execution task (running bash/python subprocess) on agent-turn cancellation

- **Severity:** Low — owner-triggered only, bounded by the 3600s tool timeout, side effects are owner-initiated; cancellation-correctness / resource-leak, not a security-boundary bug.
- **Confidence:** Confirmed by trace (and empirically reproduced). Preconditions: session owner (any authenticated user) runs a long bash or python tool inside an agent turn, then EITHER (a) presses Stop on a normal/detached run (`agent_runs.stop` -> `task.cancel` -> `agen.aclose`), OR (b) disconnects the SSE client while in compare_mode, while `stream_agent_loop` is suspended at `agent_loop.py:3127` or `:3133`.
- **Verification verdict:** real (severity Low confirmed). Reproduced: the detached `_tool_task` was NOT cancelled and ran to completion. Subprocess wrapper does handle CancelledError, but that path is never reached because nothing cancels `_tool_task`.
- **Location:** `src/agent_loop.py:3104-3133`.
- **What is wrong (invariant):** A child task owning external resources (a bash/python subprocess via `execute_tool_block`) must be cancelled/awaited on every exit path of its parent, including when the parent async generator is cancelled (client disconnect / GeneratorExit). Awaiting a Task does not cancel it when the awaiter is cancelled.
- **Why it matters:** If the streaming agent generator is cancelled while suspended at `await _progress_q.get()` (line 3127) or `await _tool_task` (line 3133), `_tool_task` is not cancelled. The orphaned `_run_tool` keeps `execute_tool_block` running — a long bash/python subprocess continues for up to the 3600s timeout with no consumer, leaking CPU/process resources and any partial side effects, after the user pressed Stop.
- **Trigger:** A user/agent session running a long bash or python tool; the user presses Stop on a normal run, or the SSE client disconnects in compare_mode, while the tool is still executing. Triggerable by the session owner (any user). Note: in default detached mode a mere SSE disconnect does NOT cancel the run by design.
- **Fix direction:** Wrap the drain loop and `await _tool_task` in `try/finally`; in finally, if `not _tool_task.done(): _tool_task.cancel()` and await it (suppressing CancelledError), so the subprocess is torn down with the turn.
- **Root cause tag:** resource-leak

```
3123  _tool_task = asyncio.create_task(_run_tool())
3126  while True:
3127      evt = await _progress_q.get()   # cancel here -> _tool_task orphaned
3128      if evt is None:
3129          break
...
3133  desc, result = await _tool_task   # cancel here -> inner task keeps running
```

### [LOW] Cancelled background HTTP MCP connect leaks its AsyncExitStack (transport/subprocess)

- **Severity:** Low — admin-only action within the trusted boundary, finite per-occurrence leak, no privilege/auth/secret-leak impact.
- **Confidence:** Confirmed by trace. Preconditions: admin connects an HTTP/OAuth MCP server (connect runs in a background asyncio task, in-flight during OAuth discovery/DCR/slow network), then calls `disconnect_server` / deletes the server (or reconnect churn) while `_connect_http` is suspended at the await on line 343 (`streamablehttp_client`) or 345 (`ClientSession`) — i.e. before line 358 stores the stack.
- **Verification verdict:** real (severity Low confirmed). The core leak (sub-claim a) is real. The auditor's secondary "state re-population for a disconnected server" claim (sub-claim b) does NOT trigger — there is no interleaving await between line 358 and task completion, so it was excluded by the verifier.
- **Location:** `src/mcp_manager.py:325-378` (`_connect_http`), `380-404` (`disconnect_server`, cancel at 384-386).
- **What is wrong (invariant):** `disconnect_server` must guarantee the server's transport/exit-stack is closed exactly once. The only `aclose()` path is via `disconnect_server` popping `self._stacks`; `_connect_http` catches only `except Exception` (line 375), so a CancelledError delivered at the pending await (line 343/345) before the stack is stored (line 358) leaves the local `AsyncExitStack` (entered httpx transport + anyio task group) never closed.
- **Why it matters:** `disconnect_server` cancels the `_connect_http` task (line 386) but does not await it, then pops `_stacks` (None at that moment). The in-flight stack's transport/ClientSession is never `aclose()`'d -> leaked httpx connection / anyio task group, with nothing to later clean it up.
- **Trigger:** Admin connects an HTTP/OAuth MCP server (background connect in flight) and disconnects/deletes it (or reconnect churn) before the connect completes. Admin-only, within the trusted boundary; reported as a cancellation-safety resource leak, not a privilege issue.
- **Fix direction:** In `_connect_http`, use `try/finally` (or `except BaseException`) to `aclose()` the stack on cancellation; in `disconnect_server`, await the cancelled connect task (suppressing CancelledError) before popping/closing state so ordering is deterministic.
- **Root cause tag:** resource-leak

```
384  task = self._connect_tasks.pop(server_id, None)
385  if task is not None and not task.done():
386      task.cancel()   # not awaited
393  stack = self._stacks.pop(server_id, None)  # likely None here
--- _connect_http ---
342  stack = AsyncExitStack()
343  transport = await stack.enter_async_context(streamablehttp_client(url, auth=provider))  # cancel here -> stack never aclosed
358  self._stacks[server_id] = stack
375  except Exception as e:  # CancelledError not caught -> no aclose
```

## Coverage

### Sub-areas inspected clean
- `service_health._bounded_map`: `out` list mutated only on the main thread inside the as_completed loop; worker threads only return dicts. ThreadPoolExecutor shut down with `wait=False`/`cancel_futures` in `finally` on every path.
- `service_health.collect_service_health`: per-subsystem `asyncio.wait_for` + `asyncio.to_thread` + overall `wait_for`; deadlines bounded, TimeoutError handled, no leaked awaitables that corrupt state.
- `task_scheduler._check_due_tasks`: snapshot of `_executing` and add-to-`_executing` both under `_executing_lock`; create_task dispatch outside the lock but IDs already reserved, so no double-dispatch.
- `task_scheduler.run_task_now` / `_run_chained`: in-flight guard add+check atomic under `_executing_lock` (no await between check and add); `force=True` bypass documented/intentional.
- `task_scheduler._execute_task finally`: handle pop guarded by `handle is current`, `_executing.discard` under lock — release semantics correct for the normal path.
- `session_manager.add_message` / `_persist_message` / `replace_messages` / `truncate_messages`: fully synchronous (no awaits), so single-threaded asyncio gives no interleaving on `session.history`; each DB op uses its own SessionLocal with commit/rollback/close.
- `embedding_lanes._get_or_reset_collection`: numpy-truthiness ValueError trap handled with explicit None/len checks; chroma calls synchronous (no await interleaving).

### Coverage gaps
- Did not exhaustively trace every executor branch in task_scheduler (`_execute_llm_task`, `_execute_research_task`, `_execute_action`) for additional CancelledError leaks beyond `_cached`; there may be other awaits inside cancellable tasks that leave partial DB state, though `_execute_task_locked`'s outer CancelledError handler (lines 840-860) covers the common case.
- ChromaDB/embedding_lanes called from a synchronous context; did not confirm whether `build_embedding_lanes` is ever run under `asyncio.to_thread` concurrently for the same base_name (could race on `get_or_create_collection` in chromadb itself).
- Did not load/trace the full agent_loop streaming generator's outer try/finally to confirm any higher-level cancellation handler cancels `_tool_task`; grep shows no finally around lines 3123-3133.

### Assumptions made
- `asyncio.CancelledError` subclasses `BaseException` (Python 3.8+), so `except Exception` does not catch it — core premise of the `_cached` and MCP-connect findings.
- `stop_task` -> `handle.cancel()` delivers CancelledError into the running `_execute_task` coroutine at its current await point.
- `_cached` callers (`_fetch_miniflux`, `_call_mcp`) perform real awaits (HTTP/MCP) long enough for a cancellation to land while the owner is the in-flight fetcher.
- Awaiting a Task and then being cancelled does NOT propagate cancellation into the awaited Task — basis for the agent_loop orphan finding.

### N/A scope areas
- Pure prompt-injection wrapper bypass and authz/IDOR are outside this concurrency-focused lens (email_pollers calendar extraction explicitly wraps untrusted email as data and is owner-scoped; not a concurrency issue).
- Admin-intended powerful capabilities (shell, MCP management, model serving) are by-design per THREAT_MODEL — the MCP-connect leak is reported only as a cancellation-safety resource leak, not a privilege issue.

### Candidates dropped as false positives
0
