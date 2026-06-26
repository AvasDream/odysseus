# Caching, Invalidation, RAG & Embeddings — Audit Report

No confirmed exploitable findings in this area: the one candidate was verified down to a non-triggerable latent footgun and dropped.

Critical: 0 | High: 0 | Medium: 0 | Low: 0; dropped false positives: 1

## Findings

No real or uncertain findings remain after verification. The single candidate (RAGManager.search() dropping the owner scope) was confirmed accurate at the code level but had no reachable exploit path in the current codebase, so it was dropped as a false positive. See the Coverage section for details.

## Coverage

### Sub-areas inspected clean
- `src/memory_vector.py`: shared collection stores no owner metadata and `search()`/`find_similar()` are NOT owner-filtered, but every consumer cross-checks the unscoped vector hits against an owner-filtered JSON source of truth (chat_processor.py:106-110 intersects with `memory_manager.load(owner=owner)`; memory_provider.recall:188 drops hits whose `entry.owner != owner`; memory_extractor.py:418-429 only treats a `find_similar` match as a dup when `_match.owner == owner` or is None). No cross-tenant memory bleed.
- `src/rag_vector.py` `_generate_doc_id`: doc ids are owner-scoped (`owner\x00text`), so two owners indexing byte-identical chunks get distinct ids and the second add is not swallowed by the first's existing-id early-return; search/keyword-fallback both apply the owner filter when owner is provided; `delete_by_source`/`remove_directory`/`rename_owner` select by metadata and stay consistent across lanes.
- `src/session_search.py`: `search_session_messages` defaults `restrict_owner=True`; `owner=None` maps to NULL-owner scope (not global) in both FTS and LIKE paths; `do_search_chats` (tool_implementations.py:75) is plumbed owner from tool_execution.py:778. No cross-user transcript leak.
- `src/embedding_lanes.py` `_get_or_reset_collection`: dimension/fingerprint/lane change triggers collection recreate + re-embed; a dimension-mismatched query against a legacy collection raises and is swallowed per-lane in `query_lanes` (degrades to no results, not corruption).
- `services/search/content.py` SSRF + size-cap path: identity encoding forced, compressed responses refused, Content-Length hard-cap preflight, streamed cap; content cache key includes effective_cap so a truncated soft-cap fetch is not served to a larger-budget request; cached content is public web data (not user-private).
- `services/search/core.py` `searxng_search_results`: only successful (non-empty) results are cached — no negative caching of empty/error results; cache key includes count and time_filter.
- `src/tool_index.py`: global tool-description index holds no user data; mcp tool ids (`mcp_<name>`) can collide across servers but only affects retrieval-candidate naming, dispatch resolves the real tool elsewhere.

### Coverage gaps
- Did not exercise ChromaDB at runtime; relied on documented contract that `collection.query` raises (rather than silently returns mismatched-dim vectors) when the query embedding dimension differs from the collection's fixed dimension.
- Did not enumerate every route to fully prove `DocsService` is unreferenced by any router at runtime; grep found only tests and the services facade importing it, but a dynamic/plugin loader was not ruled out.
- `EmbeddingClient.encode` ordering correctness depends on the remote embeddings server returning a per-item `index` field; behavior for servers that omit index and return out-of-order embeddings was not tested.

### Assumptions made
- chromadb `collection.add`/`upsert` require `len(embeddings) == len(ids)` and raise on mismatch, so a short/partial embedding response from `EmbeddingClient.encode` fails the add (caught/logged) rather than silently misaligning vectors.
- In production the app-level `rag_manager` is always the `VectorRAG` instance from `get_rag_manager()` (app.py:512), never the `RAGManager` wrapper, so chat_processor's owner-scoped RAG search is correct today.
- asyncio handlers run single-threaded; the only multi-thread mutation of the shared `content_cache_index` is via comprehensive_web_search's ThreadPoolExecutor, and any "dict changed size during iteration" in `cleanup_cache` is caught by `_cache_result`'s try/except (degrades to a skipped cache write, not a crash).

### N/A scope areas
- No Redis/memcached or distributed cache in scope — all caches here are in-process dicts + local `.cache` files on a single host, so cross-node cache key collision and distributed stampede are N/A.
- Cache stampede on miss: search/content caches are best-effort file caches with no locking, but the threat model is a trusted single-host admin workspace with low concurrency; duplicate upstream fetches on concurrent misses are an efficiency concern, not a security or correctness defect.

### Candidates dropped as false positives: 1
- **RAGManager.search() silently drops the owner scope** (proposed Low, root cause `idor`): Code facts confirmed — `RAGManager.search` (src/rag_manager.py:35-37) has no owner parameter and calls `self.vector_rag.search(query, k)`, so `where_filter` becomes None (no owner filter). However, the only consumer of the wrapper's owner-less search (`DocsService.query`, services/docs/service.py:52) is NOT wired into any FastAPI route; the live multi-user chat path correctly passes `owner` (chat_processor.py:257) against the `VectorRAG` singleton, and both production `PersonalDocsManager` instantiations inject the `VectorRAG` singleton, never the wrapper. No reachable exploit path today; a latent footgun only, dropped per triggerable-vs-theoretical discipline.
