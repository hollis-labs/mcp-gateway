# MCP Gateway

A class 1 Substrate service. It owns MCP discovery/dispatch and upstream runtime lifetimes; Tether owns caller identity, session grants and native business tools. Registry supplies declared metadata, never executable configuration or permissions.

- Read `cmd/mcp-gateway/substrate.yaml`; regenerate wiring with Substrate, never edit the generated Go file.
- Pins come only from the selected Substrate BOM. Use `substrate pins sync --app .` and `pins check`.
- `/mcp` must remain outside the app's administration identity middleware. Only accepted Unix connections select local Tether routes; all network ingress uses the narrowed remote pair.
- Every protocol operation needs fresh admission. Known credential expiry and revocation cancel in-flight work; metadata and cached fingerprints are not grants.
- `internal/gateway` is the retained discovery core; `internal/upstream` alone owns upstream lifecycle. A caller view never owns the shared pool.
- Transports call typed services/clients, never SQL or identity storage. The app database belongs to the Substrate administration identity module.
- Preserve source history and provenance. Fixtures contain neutral public paths; never reintroduce private source paths or secrets.
- Read `docs/runbook.md` before editing deployment descriptors. Option B placement belongs to fleet-install; the Cerberus config.dir/env_file workaround is manually maintained pending Folio CW-20261115-0129.
- CI requires vet, race tests, both lint configs, BOM/wiring checks and full public-history scan. No production cutover is implied by implementation or testing.
