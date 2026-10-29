package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workspace copies the real site sources and README into a temp directory so
// releases can be tried without touching the repository.
func workspace(t *testing.T) releaseOptions {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "site"), os.DirFS("../../site")); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), readme, 0o600); err != nil { //nolint:gosec // a file in t.TempDir
		t.Fatal(err)
	}
	return releaseOptions{
		options: options{
			Src: filepath.Join(dir, "site"), Out: filepath.Join(dir, "docs"),
			Readme: filepath.Join(dir, "README.md"), Base: "https://example.test/gold/",
		},
		Version: "99.0.0", Name: "Test release", Summary: "A release made by a test.", Date: "2026-11-01",
	}
}

func readVersions(t *testing.T, src string) []versionInfo {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(src, "versions.json")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var v []versionInfo
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReleasePublishesEverything(t *testing.T) {
	t.Parallel()
	r := workspace(t)
	var log bytes.Buffer
	if err := release(r, &log); err != nil {
		t.Fatal(err)
	}

	versions := readVersions(t, r.Src)
	if len(versions) < 2 || versions[0].Version != "99.0.0" || versions[0].Path != "v99.0/" {
		t.Fatalf("new version should be first: %+v", versions)
	}
	if v, _ := os.ReadFile(filepath.Join(r.Src, "VERSION")); strings.TrimSpace(string(v)) != "99.0.0" { //nolint:gosec // test temp dir
		t.Errorf("VERSION = %q", v)
	}
	for _, f := range []string{"index.html", "versions.html", "v99.0/index.html", "v99.0/assets/blue-bolt.css"} {
		if _, err := os.Stat(filepath.Join(r.Out, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	page, _ := os.ReadFile(filepath.Join(r.Out, "versions.html")) //nolint:gosec // test temp dir
	if !strings.Contains(string(page), "99.0.0") || !strings.Contains(string(page), "v99.0/index.html") {
		t.Error("versions page does not list the new version")
	}

	readme, _ := os.ReadFile(r.Readme) //nolint:gosec // test temp dir
	for _, want := range []string{
		"**99.0.0** · Test release ⭐ *current*",
		"https://example.test/gold/v99.0/index.html",
		"**0.1.0** · Phase 0: Packets |",
	} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README missing %q", want)
		}
	}
	if strings.Count(string(readme), "⭐ *current*") != 1 {
		t.Error("exactly one version should be marked current")
	}
	// A fresh release must leave everything in a state that -check accepts.
	if err := run(options{Src: r.Src, Out: r.Out, Readme: r.Readme, Base: r.Base, Check: true}, &log); err != nil {
		t.Errorf("-check fails right after a release: %v", err)
	}
}

func TestReleaseRejectsBadInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*releaseOptions)
	}{
		{"not semver", func(r *releaseOptions) { r.Version = "v2" }},
		{"same version", func(r *releaseOptions) { r.Version = "0.1.0" }},
		{"older version", func(r *releaseOptions) { r.Version = "0.0.9" }},
		{"no name", func(r *releaseOptions) { r.Name = " " }},
		{"no summary", func(r *releaseOptions) { r.Summary = "" }},
		{"bad date", func(r *releaseOptions) { r.Date = "tomorrow" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := workspace(t)
			tc.mutate(&r)
			before, _ := os.ReadFile(filepath.Join(r.Src, "versions.json")) //nolint:gosec // test temp dir
			if err := release(r, &bytes.Buffer{}); err == nil {
				t.Fatal("expected an error")
			}
			after, _ := os.ReadFile(filepath.Join(r.Src, "versions.json")) //nolint:gosec // test temp dir
			if !bytes.Equal(before, after) {
				t.Error("a rejected release changed versions.json")
			}
		})
	}
}

func TestReleaseNeverOverwritesPreservedBuild(t *testing.T) {
	t.Parallel()
	r := workspace(t)
	if err := os.MkdirAll(filepath.Join(r.Out, "v99.0"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := release(r, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Fatalf("want a refusal to overwrite, got %v", err)
	}
}

// If the build fails half way, versions.json and VERSION must be put back.
func TestReleaseRollsBackOnFailure(t *testing.T) {
	t.Parallel()
	r := workspace(t)
	if err := os.WriteFile(r.Readme, []byte("no markers here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(r.Src, "versions.json"))  //nolint:gosec // test temp dir
	versionBefore, _ := os.ReadFile(filepath.Join(r.Src, "VERSION")) //nolint:gosec // test temp dir
	if err := release(r, &bytes.Buffer{}); err == nil {
		t.Fatal("expected a failure from the README without markers")
	}
	after, _ := os.ReadFile(filepath.Join(r.Src, "versions.json"))  //nolint:gosec // test temp dir
	versionAfter, _ := os.ReadFile(filepath.Join(r.Src, "VERSION")) //nolint:gosec // test temp dir
	if !bytes.Equal(before, after) || !bytes.Equal(versionBefore, versionAfter) {
		t.Error("failed release was not rolled back")
	}
}

func TestPatchReleasesGetTheirOwnFolder(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"0.2.0": "v0.2/", "0.2.1": "v0.2.1/", "1.0.0": "v1.0/"} {
		v, err := parseSemver(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := previewPath(v); got != want {
			t.Errorf("previewPath(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestReadmeTablesAreGenerated(t *testing.T) {
	t.Parallel()
	b, err := build("../../site", "")
	if err != nil {
		t.Fatal(err)
	}
	text, err := renderReadme("../../README.md", b.data, b.pages, "https://example.test/gold")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "[Open](https://example.test/gold/)") {
		t.Error("base address should get a trailing slash")
	}
	for _, p := range b.pages {
		if !strings.Contains(text, "site/pages/"+p.Slug) {
			t.Errorf("README pages table is missing %s", p.Slug)
		}
	}
	if _, err := renderReadme("../../SECURITY.md", b.data, b.pages, ""); err == nil {
		t.Error("a file without markers must be an error, not silently skipped")
	}
}
