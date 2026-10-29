package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capture(args ...string) (code int, out, errOut string) {
	var so, se bytes.Buffer
	code = run(args, &so, &se)
	return code, so.String(), se.String()
}

func TestNewThenCheck(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "a.gold")
	if code, _, e := capture("packet", "new", "-app", "demo-app", "-o", file); code != 0 {
		t.Fatalf("new failed: %d %s", code, e)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("packet file mode = %v, want 0600", info.Mode().Perm())
	}
	code, out, e := capture("packet", "check", "-app", "demo-app", file)
	if code != 0 || !strings.HasPrefix(out, "ok ") {
		t.Fatalf("check failed: %d %q %q", code, out, e)
	}
	if code, _, e := capture("packet", "check", "-app", "other-app", file); code != 1 || !strings.Contains(e, "app_mismatch") {
		t.Errorf("want app_mismatch rejection, got %d %q", code, e)
	}
}

func TestCheckWarnsOnEdit(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "a.gold")
	if code, _, e := capture("packet", "new", "-app", "demo-app", "-name", "Mine", "-o", file); code != 0 {
		t.Fatalf("new failed: %d %s", code, e)
	}
	b, err := os.ReadFile(file) //nolint:gosec // test file in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(strings.Replace(string(b), "Mine", "Yours", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := capture("packet", "check", file)
	if code != 3 || !strings.Contains(out, "checksum_mismatch") {
		t.Fatalf("want exit 3 with checksum warning, got %d %q", code, out)
	}
}

func TestBadAppAndUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"bad app id", []string{"packet", "new", "-app", "Bad App"}, 1},
		{"no args", nil, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"version", []string{"version"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if code, _, _ := capture(tc.args...); code != tc.want {
				t.Errorf("code = %d, want %d", code, tc.want)
			}
		})
	}
}
