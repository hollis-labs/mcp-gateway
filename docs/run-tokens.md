# Verified execution-token forwarding

The gateway consumes Tether's [run-token contract](https://github.com/hollis-labs/tether/blob/main/docs/run-tokens.md) introduced by [Tether PR #634](https://github.com/hollis-labs/tether/pull/634). Tether remains the verifier; the gateway has no signing key and never treats a decoded JWT, caller metadata, environment value or attribution flag as verification.

The stdio command reads `TETHER_RUN_TOKEN` once into its frozen client options. HTTP clients send a single nonempty `X-Run-Token` header (maximum 4096 bytes) on every POST, GET and DELETE. The token is separate from the Authorization bearer and retained only in memory. Run-bearing clients refuse redirects.

Every HTTP admission, SDK operation and retained-view monitor sends the exact header and bearer to Tether's existing protected admission route. Tether verifies the signature, expiry, issuer/audience and current session/agent/task/workstream binding. A supplied token requires a nonempty verified `run` response matching the admitted session; an older backend that silently ignores the header fails closed. Absent tokens preserve legacy admission. Native Tether sessions also carry the frozen header alongside the current bearer.

A view pins the raw token as well as Tether's fingerprint: adding, changing or removing it requires a fresh MCP session. Known run expiry bounds the view's expiry and cancels its work even during an authority outage. Tether admission rechecks revocation and binding on each operation. Run verification supplies execution correlation; it grants no additional tool or machine access.

## Per-upstream policy

Only operator-owned HTTP/SSE entries can select `forward_run_token: true`; the default is false. This is independent of `proxy_service_token_file`. Registry metadata and tool arguments cannot enable it. Stdio entries reject the option. This change defines the field without changing any deployed configuration.

After fresh admission, the token and verified run URN/session enter a private request-context value. Token-bearing requests set `X-Tether-Agent-Urn` and `X-Tether-Session-Id` from those signed bindings, including a session principal without an agent; optional observation attribution cannot replace them. Only a forwarded tools/call POST to that entry's configured HTTP origin receives `X-Run-Token`. Shared initialization, pings, tools/list/catalog refresh, SSE GET streams and DELETE teardown receive none. The shared upstream pool never stores a caller token. Incoming/static run-token headers are stripped before the verified value is applied; cross-origin requests and redirects are refused. MCP metadata cannot supply the token. Upstream results and returned call errors have exact token echoes scrubbed before paging or returning them; tokens are excluded from attribution and telemetry.

Ops adoption must separately follow [`ops/docs/cerberus-handoff.md`](https://github.com/hollis-labs/shared-services/blob/main/ops/docs/cerberus-handoff.md). Both Ops gateway entries must remain disabled until that handoff's prerequisites, including this forwarding capability, are satisfied and an authorized configuration/deployment change is performed. Landing this code alone does not activate those entries or deploy/restart the gateway.

## Verification

Tests exercise actual frontend/admission/native/upstream HTTP requests with a disposable Tether-contract fixture: verified present, absent, default-off, forged/revoked admission, retained-view token removal, and result/metadata isolation. Unit tests cover duplicate/malformed headers, old backend refusal, session mismatch/expiry, origin restrictions, background methods, configuration wiring and launcher redirects. These fixtures test the gateway's use of Tether's contract, not Tether's cryptographic implementation or a production Ops call.
