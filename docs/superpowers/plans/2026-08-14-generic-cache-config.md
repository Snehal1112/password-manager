# Generic Cache Config Implementation Plan — Index

This plan was split into 4 parts (max 3 tasks each) for subagent-driven execution. Execute in order — each part depends on the previous one being complete and merged:

1. [`2026-08-14-generic-cache-config-1-cachekit-core.md`](2026-08-14-generic-cache-config-1-cachekit-core.md) — Tasks 1–3: build and fully test the generic `internal/cachekit` package (`Cloneable`/`Zeroable`/`Config`/`Interface[K,V]`, `Cache[K,V]` with TTL+LRU+Zeroable-on-remove, `NopCache`). Purely additive — whole-repo build stays clean.
2. [`2026-08-14-generic-cache-config-2-migrate-caches.md`](2026-08-14-generic-cache-config-2-migrate-caches.md) — Tasks 4–6: migrate `internal/keycache` and `internal/cache` (secrets) onto `cachekit`, add the new `internal/vaultcache` package. **Whole-repo `go build ./...` breaks intentionally until Part 4** — verify at the package level as each task specifies.
3. [`2026-08-14-generic-cache-config-3-vault-wiring-and-config.md`](2026-08-14-generic-cache-config-3-vault-wiring-and-config.md) — Tasks 7–8: wire vault caching into `VaultService`, add the unified `config.CacheConfig`/`LoadCacheConfig()`. Same intentional whole-repo-build caveat as Part 2.
4. [`2026-08-14-generic-cache-config-4-container-and-docs.md`](2026-08-14-generic-cache-config-4-container-and-docs.md) — Tasks 9–10: rewire the DI container, update `.rocketvault.yaml`/CLAUDE.md/release notes, final whole-repo `go build ./... && go vet ./... && go test ./... -race`. This is the part where the build becomes clean again.

**Spec:** `docs/superpowers/specs/2026-08-14-generic-cache-config-design.md`

Each part file is self-contained: it repeats the required plan header (Goal/Architecture/Tech Stack/Spec/Global Constraints), a scoped File Structure section, and its own Self-Review Notes — a fresh subagent working from just that one file has everything it needs.
