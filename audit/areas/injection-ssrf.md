# Injection Sinks & SSRF

SSRF, command injection, path traversal, CRLF/header/template injection, and unsafe deserialization across webhook, LLM base_url, fetch/search, upload/document, integration, cookbook-SSH, and model-probe paths — no confirmed exploitable findings.

Critical: 0 | High: 0 | Medium: 0 | Low: 0; dropped false positives: 0

No findings reached "real" or "uncertain" verification status in this area. Every candidate sink was traced from untrusted input to the dangerous use and confirmed to have validation that runs before the sink and is not bypassable within the documented (trusted-admin / private-network) threat model. The only residual items are an accepted DNS-rebinding TOCTOU note and two scope-boundary coverage gaps, all recorded below for visibility.

## Coverage

### Sub-areas inspected clean

- **Webhook SSRF (`src/webhook_manager.py`)** — `validate_webhook_url` resolves DNS for the hostname and blocks IPv4-mapped IPv6, private/loopback/link-local/reserved/multicast/unspecified ranges plus explicit metadata/localhost/`.internal` suffixes; fails closed on unresolvable hosts; re-validates at delivery time; httpx client uses `follow_redirects=False` (no redirect-chain bypass). Validation runs before any POST. Webhook CRUD + test are all `require_admin`.
- **LLM base_url SSRF (`src/url_security.py` + `routes/webhook_routes.py` sync_chat)** — token-supplied `base_url` passes through `validate_public_http_url` (blocks 0.0.0.0/8, 100.64/10 CGNAT, 127/8, 169.254/16, RFC1918, ::1, fc00::/7, fe80::/10, metadata hostnames, `.internal`/`.lan` suffixes; both IP-literal and DNS-resolved checks; fails closed on DNS error). Downstream `llm AsyncClient` created without `follow_redirects`, so public→169.254 redirect is not followed.
- **Search content fetch (`services/search/content.py` `_get_public_url`)** — capped streaming GET does manual redirect handling, re-runs `_public_http_url()` on every hop before connecting, forces `Accept-Encoding: identity` and refuses non-identity Content-Encoding (byte cap is a real memory bound), and refuses over-cap bodies via Content-Length preflight. Private-address detection mirrors `url_security`.
- **Search providers (`services/search/providers.py`)** — all provider endpoints are hardcoded vendor hosts (Brave/Tavily/Serper/Google PSE/DDG); only SearXNG instance URL is admin-settings-derived. No agent-controlled host reaches httpx; queries passed as `params` (no URL injection). `_resolve_ddg_redirect` only unwraps `uddg` from genuine duckduckgo.com `/l` paths.
- **Uploads (`routes/upload_routes.py` + `src/upload_handler.py`)** — upload IDs gated by `UPLOAD_ID_RE` (32 hex + optional alnum ext); `secure_filename` strips path separators and non-word chars; `_resolve_upload_path`/`_find_upload_path` use `os.walk(followlinks=False)` + `commonpath(realpath)` containment; download/vision routes enforce owner-or-admin. No path traversal via `file_id`.
- **Documents/PDF (`routes/document_routes.py` + `routes/document_helpers.py`)** — PDF source `upload_ids` resolved via `resolve_upload` with owner/auth checks and `_upload_path_inside` containment; `_verify_doc_owner` gates every doc read/write; signature IDs filtered by `Signature.owner` before stamping. No IDOR or path traversal.
- **Integrations (`src/integrations.py` `execute_api_call`)** — base_url normalized (http(s) scheme + hostname required, no query/fragment); path must start with `/`, rejects `://` and `#`; `_join_integration_url` lstrips leading slashes so `//evil.com` protocol-relative escape collapses to a path on the admin's own host. Integration base is admin-configured.
- **Cookbook SSH/subprocess (`routes/cookbook_routes.py`)** — `require_admin` on status/serve/probe handlers; `remote_host` validated by `_REMOTE_HOST_RE` (must start alnum, blocks `-`-prefixed SSH option injection); `ssh_port` by `_SSH_PORT_RE`; remote shell payloads built with `shlex.quote`; `session_id` gated by `_SESSION_ID_RE` before interpolation. Admin shell/model-serve is by design.
- **YouTube handler (`services/youtube/youtube_handler.py`)** — yt-dlp invoked via `create_subprocess_exec` (no shell); `video_id` embedded as a single argv element inside an `https://...watch?v=` URL, so it cannot be parsed as a flag and shell metacharacters are inert.
- **Model routes (`routes/model_routes.py`)** — every endpoint-probe/ping/create/test/discover route is `require_admin`-gated; unauthenticated `/api/models` and `/api/tools` GETs return only cached, owner-filtered lists and never trigger an outbound probe to a caller-supplied URL.

### Coverage gaps

- **DNS-rebinding TOCTOU (accepted)** — present in all three validators (`webhook_manager._is_private_url`, `url_security.validate_public_http_url`, `content._get_public_url`): the host is resolved during validation, then httpx re-resolves at connect time, so a fast-flipping attacker DNS could pass validation then connect to an internal IP. All three explicitly document this as partial defense; the validated IP is not pinned. Not weaponizable into a high-confidence static finding and consistent with the trusted-admin/private-network threat model. Flagged for visibility only.
- **Fetched-HTML wrapping not exhaustively traced** — did not exhaustively trace every consumer of `fetch_webpage_content`/search results into the agent loop to confirm untrusted fetched HTML is always wrapped via `prompt_security.untrusted_context_message` before the LLM. That wrapper-bypass lens belongs to the prompt-injection assignment; only the fetch/SSRF side was confirmed here.
- **model_routes.py partial read** — read lines 1-1313 line-by-line; the route map (decorators + auth) for the remainder (1314-2436) was extracted via grep rather than a full read. Auth gating on all probe routes was confirmed, but per-handler body logic past 1314 was not fully traced.

### Assumptions made

- `httpx.AsyncClient`/`httpx.stream` default to `follow_redirects=False` (relying on the documented httpx default since code does not set it), so a redirect to an internal host is returned as 3xx rather than followed for the LLM and webhook clients.
- `socket.getaddrinfo` in the SSRF validators returns the same address set the kernel uses for the subsequent connect within a normal (non-adversarial-DNS) window.
- Cookbook state (tasks/remote_host/ssh_port) is only admin-writable; the regex validation there is defense-in-depth on top of that trust boundary.
- `ModelEndpoint` rows (base_url) are only creatable by admins via `require_admin`-gated routes, so admin-configured endpoints intentionally pointing at private/LAN model servers are by design and not SSRF.

### N/A scope areas

- **Unsafe deserialization (yaml.load/pickle/eval)** — no `yaml.load` without SafeLoader, `pickle.loads`, or `eval` of untrusted input found in the assigned files; JSON parsed with `json.loads` throughout.
- **Template injection** — no Jinja/string-format templating of untrusted input into a server-side template engine; integration payload templates (`{{title}}`) are simple string substitution into HTTP bodies, not server-side template eval.
- **CRLF/header injection** — outbound headers built from fixed keys + admin/token-supplied API keys via httpx (which rejects newlines in header values); no untrusted value concatenated into a raw header line.

### False positives dropped

0 candidates were dropped as false positives.
