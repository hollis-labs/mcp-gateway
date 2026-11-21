package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherRunToken(t *testing.T) {
	const synthetic = "synthetic.run.proof"
	for _, tc := range []struct {
		name     string
		file     bool
		mode     os.FileMode
		contents string
		allow    string
		want     string
		wantErr  bool
	}{
		{name: "no legacy opt in"},
		{name: "legacy explicitly enabled", allow: "1", want: synthetic},
		{name: "other flag value rejected", allow: "true"},
		{name: "file preferred", file: true, mode: 0600, contents: "file.run.proof\n", want: "file.run.proof"},
		{name: "file wins over enabled legacy", file: true, mode: 0600, contents: "file.run.proof", allow: "1", want: "file.run.proof"},
		{name: "public file never falls back", file: true, mode: 0644, contents: synthetic, allow: "1", wantErr: true},
		{name: "empty file never falls back", file: true, mode: 0600, allow: "1", wantErr: true},
		{name: "oversized file", file: true, mode: 0600, contents: strings.Repeat("x", 4097), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TETHER_RUN_TOKEN", synthetic)
			t.Setenv("TETHER_RUN_TOKEN_ALLOW_ENV", tc.allow)
			t.Setenv("TETHER_RUN_TOKEN_FILE", "")
			if tc.file {
				path := filepath.Join(t.TempDir(), "run-token")
				if err := os.WriteFile(path, []byte(tc.contents), tc.mode); err != nil {
					t.Fatal(err)
				}
				t.Setenv("TETHER_RUN_TOKEN_FILE", path)
			}
			got, err := launcherRunToken()
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error status: %v", err)
			}
			if got != tc.want {
				t.Fatal("unexpected token selection")
			}
		})
	}
}

func TestLauncherRunTokenUnavailableFile(t *testing.T) {
	t.Setenv("TETHER_RUN_TOKEN", "synthetic.legacy.proof")
	t.Setenv("TETHER_RUN_TOKEN_ALLOW_ENV", "1")
	t.Setenv("TETHER_RUN_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
	if token, err := launcherRunToken(); err == nil || token != "" {
		t.Fatal("missing file must fail closed")
	}
}
