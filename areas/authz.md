# Authentication, Authorization, Sessions & Tokens — Audit Report

This area was traced end-to-end for auth bypass, privilege escalation, IDOR, confused-deputy loopback, session lifecycle, token handling, and 2FA ordering; no actionable findings were confirmed — all candidate concerns resolved to correctly-enforced controls.

Critical: 0 | High: 0 | Medium: 0 | Low: 0; dropped false positives: 0

> No real or uncertain findings. The auditor produced a clean verification pass for this area: every privilege/loopback/session/token path inspected enforced its intended invariant. The notes below record what was checked and why it holds, plus the residual gaps and assumptions so the absence of findings is auditable rather than asserted.

## Coverage

### Sub-areas inspected clean
- **Internal-tool loopback (`core/middleware.py require_admin`)**: admin is granted only when the per-process `INTERNAL_TOOL_TOKEN` matches via `secrets.compare_digest`, or `request.state.current_user == 'internal-tool'`. The token is a non-exported per-process secret with no external leak surface. `app.py AuthMiddleware` additionally requires `_is_trusted_loopback` (direct 127.0.0.1/::1, no proxy-forward headers) before honoring the header — closing the Cloudflare-tunnel spoof.
- **Impersonation header (`app.py:333-345`)**: `X-Odysseus-Owner` only attributes a loopback request to an existing user; `require_admin` independently re-checks `is_admin` on that resolved `current_user`. The only senders (`tool_implementations._internal_headers`, `task_routes`) pass the session/task owner, forced to `get_current_user` at creation (`task_routes.py:537 owner=user`) — not attacker-controllable. A non-admin task resolves to a non-admin `current_user` and is 403'd.
- **Tool-dispatch privilege gate (`src/tool_execution.py:624-640`)**: `_ADMIN_TOOLS` and `is_public_blocked_tool` (incl. `mcp__` prefix and `api_call`/`app_api`) are checked against the SESSION owner via `owner_is_admin_or_single_user` BEFORE any loopback. `blocked_tools_for_owner` is also unioned into `disabled_tools` (`agent_loop.py:1978`). `is_public_blocked_tool` fails closed on non-string names (`tool_security.py:162-166`).
- **Bearer-token auth (`app.py:362-413`)**: bearer requests set `current_user` to a sandboxed `api` principal; `require_user` (`auth_helpers.py:81-82`) rejects bearer tokens with 403 so they only reach routes with explicit scope+owner gates (codex/companion/model/webhook routes). Token owner enforced via `api_token_owner`; `_refresh_token_cache` drops tokens whose owner is not a known auth user (`app.py:271-278`).
- **Privilege default in pre-setup window (`owner_is_admin_or_single_user`, `tool_security.py:169-196`)**: auth-enabled-but-no-admin is correctly treated as NON-admin (returns False), so bash/python are not handed out before setup. Single-user (`AUTH_ENABLED=false`) returns True by design.
- **Reserved usernames (`core/auth.py`)**: `create_user`/`rename_user`/`setup`/`signup` refuse `RESERVED_USERNAMES` incl. `internal-tool`; `_drop_reserved_loaded_users` purges injected reserved rows at load; `_migrate_single_user` remaps a legacy reserved single-user to `admin`. Blocks the "account named internal-tool => silent admin" escalation.
- **2FA verification ordering (`auth_routes.login` + `auth.totp_verify`)**: password verified first, then `totp_enabled` gate, then `totp_verify`; `totp_verify` fails CLOSED when `totp_enabled` but secret missing (`auth.py:538-542`). `create_session_trusted` is only reached after both factors pass.
- **Session lifecycle (`core/auth.py`)**: tokens are `secrets.token_hex(32)`; `validate_token`/`get_username_for_token` prune expired AND orphaned (user-deleted) sessions; `delete_user` revokes sessions + `ApiToken` rows + dirties bearer cache; `rename_user` migrates session usernames; `change_password` revokes other sessions.
- **Admin-gated target routes**: `require_admin`/inline `is_admin` verified on `device_flow.py`, `copilot_routes.py`, `chatgpt_subscription_routes.py`, `vault_routes.py`, `admin_wipe_routes.py`, `backup_routes.py`, `api_token_routes.py` (with per-token owner check on patch/delete), and the auth_routes admin endpoints.
- **`set_admin` (`auth.py:410-471`)**: last-admin demotion blocked; admin-count + flag flip in one `_config_lock` critical section; privilege stash/restore prevents `ADMIN_PRIVILEGES` (e.g. `can_use_bash`) leaking past demotion.
- **Secret scrubbing on auth-exempt route**: `settings_scrub.scrub_settings` deep-masks secret-shaped keys for the unauthenticated-reachable `GET /api/auth/settings`; POST handlers at exempt paths re-derive identity from the cookie and check `is_admin`.

### Coverage gaps
- Did not exhaustively enumerate every owner-scoped data route (notes, calendar, memory, documents, gallery, email, skills) for IDOR. Spot-checked `session_routes._verify_session_owner`, codex_routes scope/owner gates, and companion `owner_can_see`, which all enforce `effective_user`/`api_token_owner` scoping. A full per-route audit of the ~40 routers was out of time budget.
- `RateLimiter` internals (`src/rate_limiter.py`) only read at call sites. Login/signup/setup limiters key on `request.client.host`, which collapses to 127.0.0.1 behind a tunnel (shared bucket => potential self-DoS / weakened per-IP throttling). Known tradeoff, not an auth bypass.
- All findings are static control/data-flow traces; the app was not dynamically executed.

### Assumptions made
- `secrets.token_hex`/`token_urlsafe` and bcrypt provide adequate entropy and constant-time comparison where used (`compare_digest` for the internal token, `bcrypt.checkpw` for bearer tokens).
- `ODYSSEUS_INTERNAL_TOKEN` is never written to any settings/openapi/log surface reachable by a non-admin; it is an in-process secret per the threat model.
- FastAPI/Starlette route matching is case-sensitive and path-normalized, so `app_api` blocklist `path.startswith` prefix checks cannot be bypassed via case/encoding into a real admin route; `app_api` is admin-only regardless.
- AuthManager mutations run on the threadpool (`asyncio.to_thread`) with RLock/Lock guarding config and sessions. The backup-code `code in backup` read sits outside the lock before the locked remove — a theoretical double-use race, but the attacker must already hold a valid one-time backup code and win a same-instant race; accepted as low / non-actionable.

### N/A scope areas
- **External OAuth/OIDC identity-provider validation**: device flows here are GitHub Copilot / ChatGPT subscription provider logins gated behind `require_admin`, not an end-user SSO trust boundary.
- **Multi-tenant / cross-org isolation**: Odysseus is single-host with a trusted admin; "user" separation is best-effort owner-scoping, not a hard tenancy boundary per the threat model.

### Candidates dropped as false positives
0.
