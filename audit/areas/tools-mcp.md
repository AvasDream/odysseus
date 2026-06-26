# Tool Parsing, Execution & MCP Subprocess Lifecycle (tools-mcp)

Audit of tool-call parsing edge cases, dispatch-time authorization re-checks, internal-tool loopback gating, MCP subprocess lifecycle, and untrusted tool-output handling. No confirmed findings; the area is inspected clean with two unresolved coverage gaps.

Critical: 0 | High: 0 | Medium: 0 | Low: 0; dropped false positives: 0

## Findings

No findings were verified as real or uncertain in this area. Every candidate inspected resolved to a correct, fail-closed control or an accepted design decision. The two items below are documented as coverage gaps (unresolved), not as confirmed findings.

## Coverage

### Sub-areas inspected clean

- **Tool DISPATCH authorization re-check** — `src/tool_execution.py` `_execute_tool_block_impl`: the `_ADMIN_TOOLS` check (line 624) and `is_public_blocked_tool()` check (line 630) both run BEFORE every dispatch branch and call `_owner_is_admin` -> `owner_is_admin_or_single_user`. `is_public_blocked_tool()` correctly gates the `mcp__` prefix (`tool_security.py:166`), so the `mcp__` dispatch branch (`tool_execution.py:889`, which has no inline admin check of its own) is still protected for non-admins. Email tools convert to `mcp__email__*` via `function_call_to_tool_block`, so they are caught by the same `mcp__` prefix gate.
- **`owner_is_admin_or_single_user`** (`tool_security.py:169-196`): fails closed pre-setup (auth configured but no admin -> returns `False`), returns `True` only for `AUTH_DISABLED` single-user mode or a confirmed `is_admin` owner; exceptions return `False`. The reserved username `internal-tool` is not a real admin user, so `is_admin()` returns `False` for it.
- **Internal-tool loopback** — agent dispatch threads `owner` (the session owner) through `execute_tool_block` and re-derives admin status from it, never trusting the `X-Odysseus-Internal-Token` loopback identity at the tool-dispatch layer. Email MCP owner is force-set server-side (`args[_EMAIL_MCP_OWNER_ARG] = owner` at `tool_execution.py:898-900`) AFTER parsing model args, so the model cannot spoof `_odysseus_owner` to read another mailbox.
- **Untrusted tool-output wrapping** — non-native path wraps all tool results via `untrusted_context_message` (`agent_loop.py:1696`). Native path returns `role:'tool'` results unwrapped (`agent_loop.py:1677-1683`), but this is documented, tested (`tests/test_tool_output_prompt_injection.py::test_native_tool_results_use_tool_role`), and covered by the system-level `UNTRUSTED_CONTEXT_POLICY` preamble (`chat_processor.py:203`, `THREAT_MODEL.md:59`) — accepted design, not a gap.
- **Tool-call parser** (`src/tool_parsing.py`): multiple/nested/extra calls are only ever parsed from the MODEL's own `round_response`, never from tool results; native-vs-fenced is mutually exclusive in `_resolve_tool_blocks` (`used_native` short-circuits fenced parsing) so no double-dispatch. Hyphenated/unmatched MCP names fail safe (dropped). `function_call_to_tool_block` fails closed for email tools on non-object args (`tool_schemas.py:1232-1235`).
- **MCP subprocess cleanup** — connect paths use `AsyncExitStack` and `aclose()` on failure (`mcp_manager.py:194-206, 255-267`); `disconnect_server` cancels in-flight HTTP/OAuth connect task, clears auth url, and `acloses` the stack on every path (`mcp_manager.py:380-404`).
- **MCP schema rendering** treats third-party tool names/types as untrusted: `_sanitize_schema_token` strips control chars and length-caps; param count + total hint length capped (`mcp_manager.py:44-92`).
- **Path confinement** for `read_file`/`write_file`/`grep`/`glob`/`ls`: sensitive-basename denylist checked first, allowlist containment via `commonpath`, workspace confinement via contextvar set once per turn and reset in `finally` (`tool_execution.py:139-288, 521-548`).

### Coverage gaps (unresolved)

- **Read-only model-serving tools exposure** — Did not exhaustively confirm whether `list_served_models` / `tail_serve_output` (neither in `NON_ADMIN_BLOCKED_TOOLS` nor `_ADMIN_TOOLS`) are actually surfaced as callable schemas to non-admin users. If they are, a non-admin could read an admin's served-model tmux/stderr output (infra logs like tracebacks/GPU errors — not end-user data), a low-severity info leak. Could not fully trace the schema-selection path to confirm exposure.
- **anyio cancel-scope semantics of `stdio_client`** — Did not trace cross-task cancel-scope behavior: if `disconnect_server`'s `stack.aclose()` executes in a different task than the one that opened the stack (e.g. `_reconnect_builtin` called from a tool-call task vs a lifespan-task disconnect), anyio can raise "cancel scope in different task" and potentially leak the MCP subprocess. Requires runtime observation to confirm; static read inconclusive.

### Assumptions made

- The MCP python client (`mcp` package) honors `AsyncExitStack.aclose()` to terminate the spawned stdio subprocess; if it leaks pipes/zombies internally that would be an upstream-library issue, not Odysseus code.
- `session.call_tool()` on a hung/malicious MCP server can block indefinitely (no timeout in `_do_call`, `mcp_manager.py:476-502`), but per THREAT_MODEL MCP servers are admin-added/trusted; a hung call stalls only that one agent turn (cancellable), so treated as robustness not security.
- The auto-reconnect-then-retry path for builtin servers (`mcp_manager.py:454-469`) can re-run a non-idempotent builtin tool (e.g. `bash`) if the subprocess dies after a side effect but before returning; `bash`/`python` are admin-only and admin-intended, so this is a robustness nit, not a privilege/injection bug.
- `build_chat_context` (`chat_processor.py`) is on the path that produces the message list passed into the agent loop, so the `UNTRUSTED_CONTEXT_POLICY` system preamble is present for native-path tool results.

### N/A scope areas

- **SSRF / webhook guards** — out of this assignment's primary files (`webhook_manager.py` / `endpoint_resolver.py`) and not reached by the tool-parsing/MCP-lifecycle control flow examined.
- **2FA / session-token crypto** — not part of tool parsing, dispatch, or MCP subprocess lifecycle.

### Dropped false positives

0 candidates were dropped as false positives.
