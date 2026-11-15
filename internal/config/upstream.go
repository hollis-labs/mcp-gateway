package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// MCPServerEntry is operator-owned runtime configuration. Registry records
// never supply executable commands, environment values or credentials.
type MCPServerEntry struct {
	ID                    string            `yaml:"id" json:"id"`
	Transport             string            `yaml:"transport" json:"transport"`
	ToolPrefix            string            `yaml:"tool_prefix" json:"tool_prefix"`
	ToolPrefixInvalid     bool              `yaml:"-" json:"-"`
	Command               string            `yaml:"command" json:"-"`
	Args                  []string          `yaml:"args" json:"-"`
	Env                   map[string]string `yaml:"env" json:"-"`
	URL                   string            `yaml:"url" json:"-"`
	Token                 string            `yaml:"token" json:"-"`
	TokenFile             string            `yaml:"token_file" json:"-"`
	ProxyServiceTokenFile string            `yaml:"proxy_service_token_file" json:"-"`
	AllowUnconfinedRemote bool              `yaml:"allow_unconfined_remote" json:"allow_unconfined_remote"`
	Enabled               *bool             `yaml:"enabled" json:"enabled,omitempty"`
	Tags                  []string          `yaml:"tags" json:"tags,omitempty"`
}

func (e MCPServerEntry) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }

// ArgumentRedactionValues keeps literal argument values out of diagnostics.
func (e MCPServerEntry) ArgumentRedactionValues() []string { return append([]string{}, e.Args...) }

func (e MCPServerEntry) StdioCredentialArgs() ([]string, string, error) {
	args := append([]string{}, e.Args...)
	if e.TokenFile == "" {
		return args, "", nil
	}
	if e.Transport != "stdio" || e.Token != "" {
		return nil, "", fmt.Errorf("token_file requires stdio without token")
	}
	for _, a := range args {
		if a == "--token" || a == "--token-file" || strings.HasPrefix(a, "--token=") || strings.HasPrefix(a, "--token-file=") {
			return nil, "", fmt.Errorf("token_file conflicts with token arguments")
		}
	}
	secret, err := ReadBearerFile(e.TokenFile)
	if err != nil {
		return nil, "", err
	}
	for _, value := range append(append([]string{}, args...), e.Command, e.TokenFile) {
		if strings.Contains(value, secret) {
			return nil, "", fmt.Errorf("credential must not appear in arguments or paths")
		}
	}
	return append(args, "--token-file", e.TokenFile), secret, nil
}

// ReadBearerFile checks the opened inode and never follows links or blocks on
// special files. Errors deliberately omit path and credential values.
func ReadBearerFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("credential path must be absolute")
	}
	// #nosec G304 -- Explicit credential path; opened inode is checked for type, owner and mode, with no symlink following.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("credential file unavailable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("credential file unavailable")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ok || int(owner.Uid) != os.Getuid() {
		return "", fmt.Errorf("credential file must be owned regular mode 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return "", fmt.Errorf("invalid credential file")
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 4 {
		return "", fmt.Errorf("invalid credential file")
	}
	for _, c := range token {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c)
		if !valid {
			return "", fmt.Errorf("invalid credential file")
		}
	}
	return token, nil
}
