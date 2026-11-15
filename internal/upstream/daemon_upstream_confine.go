package upstream

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hollis-labs/libs/harness/core/sandbox"
)

// daemonUpstreamEnvironment inherits only portable process basics. Catalog
// entries explicitly supply application settings and resolved credentials;
// unrelated daemon credentials, service-manager and loader knobs stay private.
func daemonUpstreamEnvironment(inherited []string, configured map[string]string) []string {
	env := []string{}
	for _, value := range inherited {
		name, _, _ := strings.Cut(value, "=")
		switch name {
		case "PATH", "HOME", "LANG", "TMPDIR", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION":
			env = append(env, value)
		}
	}
	for name, value := range configured {
		env = append(env, name+"="+value)
	}
	return env
}

// confineDaemonUpstream preserves host reads/network/workspace writes but makes
// the control plane read-only. Every daemon stdio launch takes this path; no
// sandbox error is permitted to fall back to the original command.
func confineDaemonUpstream(cmd *exec.Cmd, protected []string) error {
	profile := sandbox.Profile{ID: "tether-daemon-mcp-control-plane", HostFilesystem: true,
		Net: true, Subprocess: true, DenyUserServiceManager: true,
		FS: sandbox.FSSpec{Protect: protected}}
	cleanup, err := sandbox.Apply(cmd, profile, string(filepath.Separator))
	if err != nil {
		return fmt.Errorf("confine daemon MCP upstream: %w", err)
	}
	cleanup() // protect-only does not allocate runtime resources
	return nil
}
