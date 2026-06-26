# Secrets, Resource Leaks, Process/Config Lifecycle — Audit Report

Audit of secret handling, resource lifecycle, and process/config defaults in Odysseus; one confirmed Medium secret-on-disk leak amid otherwise sound controls.

Critical: 0 | High: 0 | Medium: 1 | Low: 0; dropped false positives: 0

### [MEDIUM] HuggingFace token written in plaintext into world-readable /tmp wrapper scripts (chmod 0o755)

- **Severity:** Medium — leaked secret is a local-user-readable HF gated-repo token (not master creds), adversary is a non-app local OS user on a single trusted-admin host, so the blast radius is narrower than a remote/web attacker.
- **Confidence:** Confirmed by trace. Preconditions: POSIX host (safe_chmod no-ops on Windows); admin invokes `POST /api/model/download` or the serve action with `req.hf_token` set or a stored HF token present, backend != ollama (ollama forces `hf_token=""`); a second non-app local OS user (or any process able to read `/tmp`) reads `/tmp/odysseus-tmux/<session>.sh` during the live window.
- **Verification verdict:** real (corrected severity Medium).
- **Location:** `routes/cookbook_routes.py:523, 550, 681, 801-802, 1484, 1813-1816`; `routes/shell_routes.py:399` (TMUX_LOG_DIR); `routes/cookbook_routes.py:521, 273-274` (token source).
- **What is wrong (invariant):** Secrets (HF_TOKEN) must never be persisted to a path readable by other local/unprivileged users on the host. The codebase actively enforces this everywhere else — `.app_key`, `vault.json`, and `integrations.json` are all chmod `0o600`, and `vault_routes.py` carries an explicit comment defending against `ps`/`/proc/<pid>/cmdline` reads "by any local user." Writing an HF token into a `0o755` script in shared sticky `/tmp` is an inconsistent violation of that same boundary.
- **Why it matters:** Any unprivileged local user (or any process able to read `/tmp`) can read the admin's HuggingFace access token, which grants access to the admin's gated HF repos. The download-path self-`rm` is appended inside the script after the up-to-10x retry/sleep download loop, so it only fires on completion — it persists during the (multi-hour) download and on crash/kill/tmux-kill. The serve path (write line ~1813, chmod line ~1816) has NO self-`rm` at all and lives for the entire serve lifetime and afterward.
- **Trigger:** Admin triggers `POST /api/model/download` or the serve action with an HF token. The wrapper `/tmp/odysseus-tmux/<session>.sh` is written containing `export HF_TOKEN='<token>'` then explicitly chmod `0o755`; `TMUX_LOG_DIR` (`/tmp/odysseus-tmux`) is created with default umask and never mode-restricted. Who can trigger/exploit: a co-resident local OS user on the same single host.
- **Fix direction:** Create `TMUX_LOG_DIR` with mode `0o700` and chmod secret-bearing wrapper/runner scripts to `0o600` (POSIX) instead of `0o755`; or pass `HF_TOKEN` to the child via an env file / tmux `send-keys` rather than baking it into a persistent on-disk script. The remote runner local temp copy (line ~763) needs the same restriction before scp.
- **Root cause tag:** secret-leak

```
shell_routes.py:399   TMUX_LOG_DIR = Path(tempfile.gettempdir()) / "odysseus-tmux"
cookbook_routes.py:521  req.hf_token = "" if is_ollama_download else (req.hf_token or _load_stored_hf_token())
cookbook_routes.py:523  TMUX_LOG_DIR.mkdir(parents=True, exist_ok=True)   # no mode arg -> default umask, world-traversable in shared /tmp
cookbook_routes.py:550  lines.append(f"export HF_TOKEN='{_bash_squote(req.hf_token)}'")
cookbook_routes.py:798-802  (download path)
    if not IS_WINDOWS:
        lines.append(f"rm -f '{wrapper_script}'")   # self-delete only AFTER the retry/download loop completes
        lines.append('exec "${SHELL:-/bin/bash}"')
        wrapper_script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        wrapper_script.chmod(0o755)                  # rwxr-xr-x = world-readable
cookbook_routes.py:1813-1816 (serve path)  write + safe_chmod(runner_path, 0o755); NO self-rm -> persists for whole serve lifetime
core/platform_compat.py:40-54  safe_chmod -> os.chmod(path, mode) on POSIX (confirmed real chmod)

Contrast (boundary enforced elsewhere):
  vault_routes.py:75-87        chmod 0o600 + comment: secrets world-readable via ps / /proc/<pid>/cmdline to ANY LOCAL USER
  secret_storage.py:45         .app_key chmod 0o600
  integrations.py:248          integrations.json chmod 0o600
  api_key_manager.py:23/33     .app_key "must not be group/world-readable"
  regression tests: test_api_key_file_permissions.py, test_security_regressions.py:102-112, test_vault_password_not_in_argv.py
```

## Coverage

**Sub-areas inspected clean:**
- `core/log_safety.py`: `redact_url` correctly strips userinfo + query + fragment, re-brackets IPv6, fails closed to `<endpoint>` — sound sanitizer.
- `src/secret_storage.py`: Fernet symmetric encryption; key at `data/.app_key` via `Fernet.generate_key()` + chmod `0o600`; decrypt fails closed to `''` on InvalidToken; `enc:` prefix makes migration idempotent. No weak crypto.
- `core/middleware.py`: `INTERNAL_TOOL_TOKEN = secrets.token_hex(32)` compared with `secrets.compare_digest` (timing-safe); CSP nonce uses `secrets.token_hex`. No insecure randomness or non-constant-time comparison.
- `src/integrations.py`: api_key encrypted at rest, masked in API responses (`mask_integration_secret`), file chmod `0o600`; base URL normalization rejects query/fragment and non-http(s).
- `app.py` / `launcher.py`: default binds `127.0.0.1`, `AUTH_ENABLED` defaults true, `LOCALHOST_BYPASS` defaults false gated behind `_is_trusted_loopback` with a startup warning. No unsafe `0.0.0.0`/debug/auth-disabled default.
- `src/mcp_manager.py`: connect paths wrap session setup in `AsyncExitStack` with `stack.aclose()` on exception; `disconnect_server` cancels the in-flight connect task and `aclose()`s the stack; `disconnect_all` iterates all. No obvious stack/subprocess leak.
- `src/cookbook_serve_lifecycle.py`: scheduled-stop loop re-reads state before `atomic_write_json`, kills via tmux, tolerant of already-gone sessions; uses internal-token header for loopback admin calls.

**Coverage gaps:**
- `src/llm_core.py` (2501 lines): URL-logging sinks at lines 1786/1805/1959/2021/2128/2406 log raw `target_url` without `redact_url`. `target_url` cannot contain api_key (key goes to headers; base normalization strips query) but DOES preserve userinfo if an admin sets `https://user:pass@host` — a low-value clear-text-logging inconsistency vs `model_routes` (leaks only the admin's own credential into admin-readable logs; not reported). Streaming generator cancellation paths not exhaustively audited for httpx response/stream leaks.
- `routes/cookbook_routes.py` (3488 lines): audited download + serve wrapper-script secret handling and `_launch_local_detached`, but did not fully trace every serve sub-path (vLLM/ollama/llama.cpp) for port-collision/orphan handling or additional secret materialization.
- `model_routes.py` `_refresh_caches_bg`: threads + separate SQLite session + shared `_refresh_state` dict mutated from worker futures; potential cross-thread dict races noted but not deeply analyzed (do not touch secrets/lifecycle invariants in this lens).

**Assumptions:**
- `tempfile.gettempdir()` resolves to a shared, world-traversable `/tmp` on typical POSIX deployments; on a hardened per-user TMPDIR exposure narrows but explicit chmod `0o755` still over-shares.
- `_bash_squote` only shell-escapes the token value; it does not encrypt/protect it on disk.
- `httpx.RequestError/HTTPStatusError` `str()` can include the request URL (standard httpx behavior).
- Single-host threat model treats other local unprivileged users as adversary for secret-on-disk/argv exposure — inferred from `vault_routes.py` comments.

**N/A scope areas:**
- No hardcoded credentials/default passwords found (`ODYSSEUS_ADMIN_PASSWORD` is operator-supplied, commented out in `.env.example`).
- No weak/insecure-random token generation for security tokens (all use `secrets.*`).
- Timing side-channels in secret comparison: N/A — internal token uses `compare_digest`; bcrypt handles user passwords.

**Candidates dropped as false positives:** 0
