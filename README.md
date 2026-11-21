# MCP Gateway

Standalone class 1 MCP discovery and dispatch service built on Substrate. Tether remains the caller identity, session and grant authority. This repository contains the extracted implementation; production adoption and deployment are separate work.

The gateway owns one upstream connection/process pool, per-caller native Tether connections, flat/search discovery, profile filtering, name diagnostics, numeric-safe dispatch, bounded result paging, and a refreshed Registry metadata snapshot. It never derives executable configuration or permission from Registry records.

## Run

Build with `go build ./cmd/mcp-gateway`. Configure the optional XDG file `~/.config/mcp-gateway/config.yaml` or an explicit `SUBSTRATE_CONFIG` file. The backend must be a co-located Tether version exposing its protected `/gateway/mcp/` Unix-socket routes.

```yaml
mcp-gateway:
  tether_socket: /path/to/tether/control.sock
  upstreams: []
  allowed_hosts: []
```

`mcp-gateway serve --addr unix:/absolute/path/gateway.sock` accepts local callers. Every TCP ingress, including loopback and reverse proxies, uses Tether's remote admission/native pair and requires an issued session-bound agent credential. HTTP headers, query parameters and tool metadata cannot choose the local pair. The local socket is created with mode 0600.

`mcp-gateway mcp --addr unix:/absolute/path/gateway.sock --token-file /absolute/path/caller.key` forwards stdio to the service. It reads the caller credential once, starts no upstream itself, and never replays an uncertain tool call. Optional selectors are `--profile` and `--discovery-mode flat|search`.

The stdio command reads the owned mode-0600 file named by `TETHER_RUN_TOKEN_FILE` once and carries it separately as `X-Run-Token`. Direct HTTP clients must send the same header on every request. See [verified run-token forwarding](docs/run-tokens.md) for the opt-in upstream policy and Tether prerequisite.

The gateway's own Substrate identity protects administration only. See [identity bootstrap](docs/identity-bootstrap.md) and [operations](docs/runbook.md).

## MCP surface

Search mode lists `mcp_gateway_tool_list`, `mcp_gateway_tool_search`, `mcp_gateway_tool_call`, `mcp_gateway_status` and `mcp_gateway_result_next`, plus eligible pinned tools. Flat mode lists eligible real tools, status and paging. Native business tool names remain `tether_*`; old gateway wrapper aliases are absent.

Each HTTP and SDK operation obtains fresh Tether admission. The opaque fingerprint binds a view to its principal, policy and profile. Revocation or changed authority cancels the view; the latest known credential expiry cancels in-flight work even during an authority outage. Refresh can extend an equivalent view without regressing its expiry. SessionPolicy.Servers restricts configured upstreams; native tools retain Tether's separate scope and profile checks.

Registry snapshots refresh every minute and publish only after all pages validate. An outage retains the last whole snapshot with an explicit stale indicator. Missing metadata stays unknown; routing continues from observed upstream declarations. Definition hashes must match before a reviewed classification is associated with a live tool. Correlation hints are resolved against the snapshot and remain distinct from verified identity. Caller attribution comes from Tether `/auth/context` using the admitted bearer and is forwarded only after matching the principal and session.

## Verification and history

```sh
go vet ./...
go test -race ./...
go run github.com/hollis-labs/substrate/cmd/substrate pins check --app .
golangci-lint run ./...
golangci-lint run --config .golangci.transport.yml ./...
go run github.com/hollis-labs/substrate/cmd/substrate scan-public --ref HEAD
```

The core, selected upstream runtime and stdio forwarding histories are filtered from `hollis-labs/tether` at `6840a09a22fa12cfc3d6d321deca7d6075e3b618`; authorship and dates are retained. [SOURCE_HISTORY.json](SOURCE_HISTORY.json) maps original commits to extracted commits. The original MIT license remains in LICENSE. Substrate/Folio supplied the application shell; demo CRUD was removed.

Personal fixture paths were sanitized throughout retained core history. Query labels and scorer behavior are unchanged. The reviewed fixture-only rebaseline preserved all scored-query ranks, recall and MRR; no-match totals fell by one per scorer, and BM25 median response bytes changed 3155→3159 overall and 3175→3181 for held-out queries. No scorer tuning or code-mode experiment is included.
