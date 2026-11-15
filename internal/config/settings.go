package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hollis-labs/libs/security/secrets"
	"gopkg.in/yaml.v3"
)

type Settings struct {
	AllowedHosts       []string `yaml:"allowed_hosts"`
	TetherSocket       string   `yaml:"tether_socket"`
	TetherControlPaths struct {
		Catalog string `yaml:"catalog"`
		Run     string `yaml:"run"`
		State   string `yaml:"state"`
	} `yaml:"tether_control_paths"`
	ProtectedPaths    []string         `yaml:"protected_paths"`
	Upstreams         []MCPServerEntry `yaml:"upstreams"`
	RegistryURL       string           `yaml:"registry_url"`
	RegistryTokenFile string           `yaml:"registry_token_file"`
}

func Parse(v any) (Settings, error) {
	var out Settings
	raw, err := yaml.Marshal(v)
	if err != nil {
		return out, fmt.Errorf("invalid gateway configuration")
	}
	d := yaml.NewDecoder(strings.NewReader(string(raw)))
	d.KnownFields(true)
	if err = d.Decode(&out); err != nil {
		return out, fmt.Errorf("invalid gateway configuration: %w", err)
	}
	if !filepath.IsAbs(out.TetherSocket) {
		return out, fmt.Errorf("mcp-gateway.tether_socket must be an absolute protected Unix socket path")
	}
	if (out.RegistryURL == "") != (out.RegistryTokenFile == "") {
		return out, fmt.Errorf("registry URL and token file must be configured together")
	}
	for _, e := range out.Upstreams {
		values := append(append([]string{}, e.Args...), e.URL, e.Command, e.Token)
		for _, v := range e.Env {
			values = append(values, v)
		}
		for _, value := range values {
			if strings.Contains(value, "${") || secrets.IsRef(value) || strings.HasPrefix(value, "file://") {
				return out, fmt.Errorf("secret references and environment interpolation are unsupported; use credential files and explicit values")
			}
		}
		if !e.IsEnabled() {
			continue
		}
		if e.Transport != "stdio" && e.Transport != "http" && e.Transport != "sse" {
			return out, fmt.Errorf("unsupported upstream transport")
		}
		if e.Transport == "stdio" {
			for _, p := range []string{out.TetherControlPaths.Catalog, out.TetherControlPaths.Run, out.TetherControlPaths.State} {
				if !filepath.IsAbs(p) {
					return out, fmt.Errorf("stdio requires explicit Tether catalog, run and state protection directories")
				}
				out.ProtectedPaths = append(out.ProtectedPaths, p)
			}
		}
		if e.Transport == "stdio" && e.Command == "" {
			return out, fmt.Errorf("stdio upstream requires a command")
		}
		if e.TokenFile != "" && e.Transport != "stdio" {
			return out, fmt.Errorf("token_file requires stdio")
		}
		if e.Transport != "stdio" && e.URL == "" {
			return out, fmt.Errorf("HTTP/SSE upstream requires a URL")
		}
	}
	return out, nil
}
