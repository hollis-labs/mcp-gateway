# MCP Gateway

Standalone class-1 MCP gateway application, under development.

This first extraction contains the behavior-preserving gateway core. It does
not yet expose a runnable service. Tether authority and native-tool integration,
upstream transport ownership, and Registry integration are separate assembly
steps. Deployment and consumer adoption are not part of this extraction.

## Core

`internal/gateway` implements tool discovery, flat/search presentation,
profile restrictions, naming diagnostics, result paging and search evaluation.
Its policy inputs come from an authority; the package does not issue identity
or grant permissions.

```sh
go test -race ./...
go vet ./...
go test ./internal/gateway -run '^TestSearchEval$' -count=1 -v
```

The query labels and scorer retain their original behavior. Personal paths in
the catalog fixture are replaced with neutral public examples throughout the
retained history. The driver approved the resulting fixture-only baseline
adjustments: no scored-query ranks, recall or MRR changed; no-match totals fell
by one for each scorer, and BM25 median response bytes changed from 3155 to
3159 overall and from 3175 to 3181 on held-out queries. No ranking experiment
or tuning is included.

## Source history

The initial history is filtered from
[`hollis-labs/tether`](https://github.com/hollis-labs/tether) at
`6840a09a22fa12cfc3d6d321deca7d6075e3b618`, selecting
`internal/mcpgateway` and relocating it to `internal/gateway` with
`git filter-repo`. The retained commits preserve their authors and dates;
path filtering necessarily changes commit identities. Original source license
and copyright are retained in `LICENSE`.
`SOURCE_HISTORY.json` maps retained source commits to their sanitized extracted
commits. Catalog fingerprints are recalculated after sanitization.

The following preparation changes the package name to `gateway` and supplies
an independent module with the source's dependency versions. Tether's active
implementation remains in place until separately reviewed adoption and removal.
