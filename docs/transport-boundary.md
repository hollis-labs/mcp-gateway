# Transport boundary

HTTP administration handlers and the MCP frontend use typed services and clients. They do not import SQL, the database module or application storage. The composition root starts Substrate modules and selects listener authority; the identity module owns its administration database.

The transport lint configuration covers `internal/api`, `internal/frontend`, `internal/mcp` and `internal/cli`. Runtime configuration is operator-owned. Registry cache, telemetry and Tether authority are separate from executable upstream configuration.
