package main

import (
	"fmt"

	"github.com/hollis-labs/mcp-gateway/internal/client"
	"github.com/hollis-labs/mcp-gateway/internal/forward"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func mcpCmd() *cobra.Command {
	var address, tokenFile, profile, mode, label string
	cmd := &cobra.Command{Use: "mcp", Short: "Forward the gateway over stdio using a delegated caller credential", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if address == "" || tokenFile == "" {
			return fmt.Errorf("--addr and --token-file are required")
		}
		c, err := client.New(address, tokenFile)
		if err != nil {
			return err
		}
		opts := client.MCPOptions{ClientLabel: label}
		if cmd.Flags().Changed("profile") {
			opts.Profile = &profile
		}
		if cmd.Flags().Changed("discovery-mode") {
			opts.DiscoveryMode = &mode
		}
		return forward.Run(cmd.Context(), c, opts, &mcp.StdioTransport{})
	}}
	cmd.Flags().StringVar(&address, "addr", "", "Gateway HTTP origin or unix:/absolute/socket")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "Owned mode-0600 file containing the Tether caller bearer")
	cmd.Flags().StringVar(&profile, "profile", "", "Tether profile selector")
	cmd.Flags().StringVar(&mode, "discovery-mode", "", "flat or search")
	cmd.Flags().StringVar(&label, "client-label", "", "Unverified telemetry label")
	return cmd
}
