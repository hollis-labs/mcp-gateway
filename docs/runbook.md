# Runtime configuration and deployment

This extraction has not activated a production service or changed any Tether consumer or grant. Deployment descriptors are templates, with a generic fleet host and port 8080. Resolve all `~` paths before registering a resource; create the selected configuration directory first.

The binary and release placement belong to fleet-install (Cerberus Option B). Cerberus starts the installed symlink; it does not build or install the application. Build and release artifacts include `deploy.yaml`, `project.yaml` and `mcp-gateway.cerberus.yaml`.

The Folio-generated Cerberus descriptor was manually completed with `config.dir: ~/.config/mcp-gateway` and `config.env_file: ~/.config/mcp-gateway/service.env`. The directory must exist independently of any source checkout, and the environment file must be private. Preserve these fields when regenerating until Folio CW-20261115-0129 fixes this scaffold gap. The env file selects private `SUBSTRATE_CONFIG` and any XDG overrides; no credential or real fleet topology belongs in this repository.

## Upstreams and protection

Operator configuration owns upstream IDs, transport, command/args/env or URL, optional prefix/tags and credential-file references. `token_file` is for stdio and is passed as `--token-file`; `proxy_service_token_file` is for HTTP/SSE and is loaded only by the shared runtime. Files must be absolute, regular, owned by the process user and mode 0600; links and special files are refused. HTTP/SSE credentials are origin-bound and redirects are refused.

The gateway deliberately does not resolve Tether catalog `${VAR}`, `file://`, keychain or helper secret references. Unsupported reference syntax is rejected; provide explicit values or supported credential-file fields. Literal argument/environment values are included in diagnostic redaction. Do not copy an unresolved Tether catalog into this configuration.

Enabled stdio upstreams require all three absolute, existing directories:

```yaml
mcp-gateway:
  tether_socket: /path/to/tether/control.sock
  tether_control_paths:
    catalog: /path/to/tether/catalog
    run: /path/to/tether/run
    state: /path/to/tether/state
  protected_paths: []
  upstreams:
    - id: example
      transport: stdio
      command: /absolute/path/example
      args: [mcp]
      token_file: /absolute/path/example.key
```

The app automatically adds its own configuration, database, identity, secrets and Registry credential directories, plus the Tether socket parent. `protected_paths` adds any project-layer catalog authority directories loaded by Tether; the external gateway cannot discover those layers. A missing or unresolvable root prevents startup. Sandbox failure never falls back to an unconfined launch. Inherited confinement preserves host reads/network and protects control-plane writes; this is not a filesystem confidentiality boundary.

HTTP/SSE upstreams cannot be sandboxed locally; the inherited policy requires explicit `allow_unconfined_remote: true` for each one. Disabled/unavailable origins remain diagnostic states, never fabricated tools. Remote catalogs refresh every minute and reconnect without replaying uncertain tool calls. A configuration change requires a gateway restart; new Tether-granted origins absent from this runtime are reported `pending_restart`.

## Run-token forwarding

HTTP/SSE upstreams can opt in with `forward_run_token: true` (default false). This forwards only the calling tool request's freshly Tether-verified `X-Run-Token`; it does not substitute a service bearer or send a caller token during shared initialization, catalog refresh, ping, background streams or teardown. Stdio entries reject this HTTP-only option. See [the trust boundary and prerequisites](run-tokens.md), including the Ops handoff prerequisite.

## Metadata and deferred cutover work

Configure `registry_url` and `registry_token_file` together for live metadata. The client reads `/v1/snapshot`, pages at Registry's supported maximum, validates the envelope and boundary, and atomically replaces its cache. Missing/outdated classifications do not invent tool safety or approval. Approval orchestration remains outside this slice; no new approval authority is introduced.

SourceProxy durable references and Tether retained-recovery/history receipts are not connected in this extraction; status reports that explicitly. The bounded observation endpoint is usable now. Adoption requires separately wiring those ports, protecting every relevant Tether project/catalog authority layer, verifying deployment paths and scopes, and reviewing consumer cutover. No new grant issuer or approval service is introduced.

Native Tether resources are relayed from the per-caller native endpoint. The source has no resource-template or prompt registrations. The extracted stdio forwarder retains the source's tools/list, tools/call and ping relay surface; resource access uses HTTP directly until a separately reviewed forwarder extension.

## Contract checks

Normal tests use disposable local fixtures. Opt-in `TestRealTetherBackend` runs inside Tether's `TestBackendConsumerIntegration` harness with a real issued identity, temporary store and protected Unix backend. Opt-in `TestRealRegistrySnapshot` runs under Registry's real SQLite service/HTTP harness, with multiple pages and a reviewed tool. Neither accesses a production daemon or catalog. Rebuild consumer test binaries against the candidate before repeating those paired checks.
