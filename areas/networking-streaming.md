# Networking, Streaming, Retry/Backoff, Timeouts

Audit of retry/backoff correctness, timeout handling, SSE/streaming cleanup, chunk-boundary parsing, cancellation propagation, and partial-failure handling across the LLM client, durable-run manager, and chat streaming routes.

Critical: 0 | High: 0 | Medium: 0 | Low: 0; dropped false positives: 0

## Result

No defects were raised in this area. The auditor inspected the retry loop, streaming context management, SSE parsing, durable-run fan-out, chat-stream cancellation handling, and the health fan-out, and found each to uphold its invariant. No candidate finding reached a "real" or "uncertain" verdict, so there is nothing to report as a defect. The remaining items below are recorded for traceability: what was inspected and found clean, residual coverage gaps, and the assumptions the clean verdicts rest on.

## Coverage

### Sub-areas inspected clean

- `src/llm_core.py` `llm_call_async` retry loop (lines 1768-1814): bounded `max_retries=3`, retries only 429/502/503/504 and connect/request errors, fixed 0.5s delay; non-streaming completions are idempotent in effect (no tool side effects), errors are NOT cached, cache check precedes the loop. No unbounded retry, no retry-of-permanent-4xx (only 429/5xx).
- `src/llm_core.py` `stream_llm` (all provider branches): each uses httpx `client.stream(...)` as an async-with context manager, so read timeout (`httpx Timeout read=stream_timeout`) bounds a stalled mid-stream (no infinite hang); connect/read/network exceptions are caught and surfaced as `event:error` chunks; the async-with guarantees connection release on normal completion and on caught exceptions.
- `src/llm_core.py` `_HarmonyStreamRouter`: chunk-boundary marker splitting handled via `_harmony_suffix_hold_len` holding back partial-marker suffixes and re-prepending on next feed; `flush()` at `[DONE]` and end-of-stream emits the tail.
- `src/llm_core.py` OpenAI-compat SSE parsing uses `r.aiter_lines()` which reassembles `data:` lines across network chunks; tool_call accumulator guards null arguments (or '') and `index=None` collision; usage capture gated correctly.
- `src/llm_core.py` host-health maps (`_dead_hosts`/`_host_fails`/`_response_cache`) are guarded by `threading.Lock` because sync `llm_call` runs in the threadpool while async runs on the loop; cache eviction uses `pop()` not `del` to avoid cross-thread KeyError; cache is bounded at 128.
- `src/agent_runs.py` durable-run manager: `subscribe()` registers queue before replay so no events are missed, dedups replay-vs-live via `seq>=next_seq`, heartbeat on 10s idle, grace-period eviction is identity-checked against run replacement; `_drain` runs to completion regardless of subscribers and `aclose()`s the wrapped generator on cancellation to trigger the partial-save path; `start()` cancels and awaits the prior in-flight run before writing to keep saves sequential.
- `routes/chat_routes.py` `chat_stream`: chat-mode and agent-mode both catch `(CancelledError, GeneratorExit)` on client disconnect, save the partial response exactly once, re-raise, and pop `_active_streams` in a finally; `_safe_stream` wrapper guarantees `_active_streams` cleanup; `_stream_set` uses `.get()` to avoid a KeyError race with sibling finally pops.
- `routes/chat_routes.py` resume/stop/stream_status endpoints all enforce `_verify_session_owner` (DB owner match, 404 on mismatch) before subscribing/stopping a session run — no IDOR into another user's detached run.
- `src/service_health.py` fan-out: ThreadPoolExecutor bounded, `as_completed` with total budget, `ex.shutdown(wait=False, cancel_futures=True)` in finally; per-subsystem and aggregate deadlines via `asyncio.wait_for`; admin-only and non-intrusive.
- `src/agent_loop.py` round loop: per-read inactivity timeout plus a wall-clock `_round_deadline` guard against a forever-trickling stream; break on deadline is an intentional runaway cap.

### Coverage gaps

- The deferred close of an abandoned async generator on `break` (`agent_loop.py:2610` breaking out of `async for ... stream_llm_with_fallback`) relies on CPython refcount + asyncio's async-gen finalizer to run `aclose()` and release the httpx connection. This is a soft/deferred cleanup, not a hard leak, and on a trusted single host is not security-impacting; actual GC timing was not instrumented to confirm worst-case lingering.
- `model_routes.py` SSE probe streams (`_stream` at 1563, re-probe at ~1991) are sync generators run in the threadpool; client disconnect only stops iteration at the next yield, so an in-flight blocking `_probe_single_model` continues until its per-probe timeout. Bounded and admin-only; not traced exhaustively for every probe path.
- Did not exhaustively trace every provider-specific header/payload builder (Anthropic/Ollama/copilot/kimi) for header-injection from model/url values, as those originate from admin-configured endpoints (trusted per threat model).

### Assumptions made

- `httpx.Timeout(read=...)` fires when no bytes arrive within the window during streaming, bounding a stalled mid-stream — standard httpx behavior.
- `httpx aiter_lines()` reassembles SSE `data:` lines split across TCP/network chunks, so JSON events are not corrupted by chunk boundaries.
- asyncio's async-generator finalizer (installed by the running event loop) eventually calls `aclose()` on an abandoned async generator once its refcount drops to zero, cascading `GeneratorExit` into nested `async with client.stream(...)` blocks to release the connection.
- LLM chat completions called via `llm_call_async` carry no external side effects (no tool execution), so retrying a timed-out/5xx POST is safe beyond redundant token spend.
- Starlette raises `CancelledError`/`GeneratorExit` into a `StreamingResponse` generator promptly on client disconnect, which the `chat_stream` except blocks rely on for partial-save and cleanup.

### N/A scope areas

- No HTTP/2 multiplexing concerns: the shared client sets `http2=False` (`llm_core.py:257`).
- No thread-based race in the async streaming generators themselves: they run on the single event loop; the only cross-thread state (host-health maps, response cache) is already lock-guarded.
- Webhook SSRF and MCP subprocess networking are out of this lens (covered by other assignments); not analyzed here.

### Candidates dropped as false positives

0
