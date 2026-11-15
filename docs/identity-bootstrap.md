# Administration identity

The Substrate identity module protects this application's administration API. Create the owner offline with `mcp-gateway identity setup --username owner`. Create a separate administration key with `mcp-gateway identity key create --name observer --scope mcp-gateway.read --out /absolute/path/admin.key`.

These keys do not authorize MCP calls. `/mcp` accepts the original Tether caller bearer and checks Tether admission on every operation. No administrator credential is substituted for that bearer, and no open HTTP bootstrap is provided.

The identity database and signing key live under `MCP_GATEWAY_DATA_DIR`, else `$XDG_DATA_HOME/mcp-gateway`, else `~/.local/share/mcp-gateway`. Secret-backend state lives under `$XDG_STATE_HOME/mcp-gateway/secrets` or `~/.local/state/mcp-gateway/secrets`. Back up the identity database and signing key together using the established offline/SQLite backup procedure.

`GET /api/gateway/status` and `GET /api/gateway/events?limit=50` require `mcp-gateway.read`. Events are newest first, bounded to 100 per response and 1024 in memory. They contain tool/origin, timing, outcome, admitted principal/session, classification and correlation state. Arguments, result bodies and credentials are not retained. This is process-local observation, not a Tether history receipt.
