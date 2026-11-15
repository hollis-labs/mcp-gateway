package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hollis-labs/mcp-gateway/internal/api"
	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/config"
	"github.com/hollis-labs/mcp-gateway/internal/frontend"
	"github.com/hollis-labs/mcp-gateway/internal/hostguard"
	"github.com/hollis-labs/mcp-gateway/internal/registry"
	"github.com/hollis-labs/mcp-gateway/internal/telemetry"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	"github.com/hollis-labs/substrate/module"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"
	"github.com/spf13/cobra"
)

func serveCmd(ctx context.Context, app *module.App) *cobra.Command {
	var addr string
	cmd := &cobra.Command{Use: "serve", Short: "Serve MCP and the administration API", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if addr != "" {
			cfg, _ := app.Config["httphost"].(map[string]any)
			cfg["addr"] = addr
		}
		return serve(ctx, app, nil)
	}}
	cmd.Flags().StringVar(&addr, "addr", "", "Listener address or unix:/absolute/path")
	cmd.Flags().Bool("managed", false, "Supervised run; class 1 auth is always enforced")
	return cmd
}

type localIngressKey struct{}

func serve(ctx context.Context, app *module.App, ready func(net.Addr)) error {
	if guard := auth.Guard(app); guard == nil || string(guard.Mode()) != "enforce" {
		return errors.New("class 1 applications require enforced auth")
	}
	id := identity.From(app)
	if id == nil {
		return errors.New("identity module must be started")
	}
	cfg, err := config.Parse(app.Config[substrateApp])
	if err != nil {
		return err
	}
	// Derive our control roots; the external Tether catalog/run/state roots
	// remain explicit because the gateway does not load Tether configuration.
	roots := append([]string{}, cfg.ProtectedPaths...)
	roots = append(roots, filepath.Dir(cfg.TetherSocket))
	for _, path := range [][]string{{"config", "dir"}, {"database", "sqlite", "path"}, {"identity", "key_file"}, {"secrets", "state_dir"}} {
		var value any = app.Config
		for _, key := range path {
			m, _ := value.(map[string]any)
			value = m[key]
		}
		if p, ok := value.(string); ok && p != "" {
			if path[len(path)-1] == "path" || path[len(path)-1] == "key_file" {
				p = filepath.Dir(p)
			}
			roots = append(roots, p)
		}
	}
	if cfg.RegistryTokenFile != "" {
		roots = append(roots, filepath.Dir(cfg.RegistryTokenFile))
	}
	runtime, err := upstream.New(cfg.Upstreams, roots)
	if err != nil {
		return err
	}
	defer runtime.Close()
	registryCache := registry.New(cfg.RegistryURL, cfg.RegistryTokenFile)
	runctx, cancel := context.WithCancel(ctx)
	defer cancel()
	registryDone := make(chan struct{})
	go func() { defer close(registryDone); registryCache.Run(runctx) }()
	defer func() { cancel(); <-registryDone }()
	recorder := &telemetry.Recorder{}
	localAuthority, err := authority.New(cfg.TetherSocket, false)
	if err != nil {
		return err
	}
	remoteAuthority, err := authority.New(cfg.TetherSocket, true)
	if err != nil {
		return err
	}
	local, err := frontend.New(runctx, frontend.Options{Authority: localAuthority, Runtime: runtime, Registry: registryCache, Observer: recorder, HostGuarded: true})
	if err != nil {
		return err
	}
	defer local.Close()
	remote, err := frontend.New(runctx, frontend.Options{Authority: remoteAuthority, Runtime: runtime, Registry: registryCache, Observer: recorder, HostGuarded: true})
	if err != nil {
		return err
	}
	defer remote.Close()
	api.RegisterScopes(auth.ScopeTable(app))
	admin, err := httphost.Handler(app, httphost.Options{Routes: api.New(registryCache, recorder), NotFound: httphost.NotFoundFlat})
	if err != nil {
		return err
	}
	admin = id.Middleware(admin)
	// /mcp validates only Tether credentials. The app's admin identity must never
	// translate or reject that bearer before the delegated admission boundary.
	handler := hostguard.Handler(cfg.AllowedHosts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			isLocal, _ := r.Context().Value(localIngressKey{}).(bool)
			if isLocal {
				local.ServeHTTP(w, r)
			} else {
				remote.ServeHTTP(w, r)
			}
			return
		}
		admin.ServeHTTP(w, r)
	}))
	hostcfg, _ := app.Config["httphost"].(map[string]any)
	addr, _ := hostcfg["addr"].(string)
	opts := httphost.ServeOptions{Ready: func(a net.Addr) {
		slog.Info("mcp-gateway listening", "addr", a.String())
		if ready != nil {
			ready(a)
		}
	}, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		_, ok := c.(*net.UnixConn)
		return context.WithValue(ctx, localIngressKey{}, ok)
	}}
	if strings.HasPrefix(addr, "unix:") {
		ln, err := httphost.ListenUnix(strings.TrimPrefix(addr, "unix:"), 0600)
		if err != nil {
			return err
		}
		opts.Listener = ln
	}
	return httphost.Serve(ctx, app, handler, opts)
}
