package upstream

import (
	"github.com/hollis-labs/libs/security/secrets/redact"
	"github.com/hollis-labs/mcp-gateway/internal/config"
	"net/url"
	"regexp"
	"strings"
)

func probeRedactor(entries []config.MCPServerEntry) *redact.Set {
	out := proxyRedactionSet(entries)
	for _, entry := range entries {
		out.Add(entry.URL)
		if endpoint, err := url.Parse(entry.URL); err == nil {
			out.Add(endpoint.Hostname())
			out.Add(endpoint.Host)
		}
		for i, arg := range entry.Args {
			if i > 0 {
				switch entry.Args[i-1] {
				case "--token", "--api-key", "--secret", "--password":
					out.Add(arg)
				}
			}
			for _, prefix := range []string{"--token=", "--api-key=", "--secret=", "--password="} {
				if strings.HasPrefix(arg, prefix) {
					out.Add(strings.TrimPrefix(arg, prefix))
				}
			}
			if strings.Contains(arg, "://") {
				out.Add(arg)
			}
		}
		if entry.URL != "" {
			withoutScheme := strings.TrimPrefix(strings.TrimPrefix(entry.URL, "https://"), "http://")
			out.Add(withoutScheme)
		}
	}
	return out
}

var diagnosticURL = regexp.MustCompile(`(?i)(?:https?|sse)://[^\s"<>]+`)

func redactProbeText(secrets *redact.Set, text string) string {
	return diagnosticURL.ReplaceAllString(secrets.Redact(text), redact.Marker)
}
