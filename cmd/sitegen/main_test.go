package main

import (
	"bytes"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

var (
	refRE = regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	idRE  = regexp.MustCompile(`\sid="([^"]+)"`)
)

// Every internal link and anchor in the built site must resolve, and every
// page must have the pieces assistive technology and search rely on.
func TestBuiltSiteLinksResolve(t *testing.T) {
	t.Parallel()
	b, err := build("../../site", "")
	if err != nil {
		t.Fatal(err)
	}
	files := b.files
	ids := map[string]map[string]bool{}
	for name, b := range files {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		ids[name] = map[string]bool{}
		for _, m := range idRE.FindAllSubmatch(b, -1) {
			ids[name][string(m[1])] = true
		}
	}

	// Preserved builds are written by -snapshot, so they are not in the
	// in-memory build. TestPreservedBuildsExist checks they are on disk.
	d, err := loadSiteData(os.DirFS("../../site"))
	if err != nil {
		t.Fatal(err)
	}

	pages := 0
	for name, b := range files {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		pages++
		for _, need := range []string{`<html lang="en">`, `<meta name="viewport"`, `<title>`, `<meta name="description"`, `<main id="main">`, `class="bb-skip"`} {
			if !bytes.Contains(b, []byte(need)) {
				t.Errorf("%s: missing %s", name, need)
			}
		}
		if n := bytes.Count(b, []byte("<h1")); n != 1 {
			t.Errorf("%s: has %d h1 elements, want 1", name, n)
		}
		for _, m := range refRE.FindAllSubmatch(b, -1) {
			ref := string(m[1])
			if strings.Contains(ref, "://") || strings.HasPrefix(ref, "mailto:") {
				continue
			}
			preserved := false
			for _, v := range d.Versions {
				preserved = preserved || strings.HasPrefix(ref, v.Path)
			}
			if preserved {
				continue
			}
			target, frag, _ := strings.Cut(ref, "#")
			if target == "" {
				target = name
			}
			target = path.Clean(target)
			if _, ok := files[target]; !ok {
				t.Errorf("%s: broken link %q", name, ref)
				continue
			}
			if frag != "" && ids[target] != nil && !ids[target][frag] {
				t.Errorf("%s: link %q points to a missing anchor", name, ref)
			}
		}
	}
	if pages < 6 {
		t.Errorf("built only %d pages", pages)
	}
}

func TestEveryVersionIsListedAndOneIsCurrent(t *testing.T) {
	t.Parallel()
	d, err := loadSiteData(os.DirFS("../../site"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) == 0 {
		t.Fatal("no versions")
	}
	for _, v := range d.Versions {
		if !strings.HasSuffix(v.Path, "/") || strings.HasPrefix(v.Path, "/") {
			t.Errorf("version %s: path %q should look like v0.1/", v.Version, v.Path)
		}
	}
}

func TestSnapshotNameIsConfined(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"../evil", "a/b", ".hidden"} {
		if err := run(options{Src: "../../site", Out: t.TempDir(), Snapshot: bad}, &bytes.Buffer{}); err == nil {
			t.Errorf("snapshot %q accepted", bad)
		}
	}
}

func TestSnapshotWritesPreservedCopy(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	if err := run(options{Src: "../../site", Out: out, Snapshot: "v0.1"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"index.html", "v0.1/index.html", "v0.1/assets/blue-bolt.css", ".nojekyll"} {
		if _, err := os.Stat(out + "/" + p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	if err := run(options{Src: "../../site", Out: out, Check: true}, &bytes.Buffer{}); err != nil {
		t.Errorf("fresh output should pass -check: %v", err)
	}
	if err := os.WriteFile(out+"/index.html", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(options{Src: "../../site", Out: out, Check: true}, &bytes.Buffer{}); err == nil {
		t.Error("stale output should fail -check")
	}
}

// A version listed on the site must have its preserved build committed in
// docs/, or its "Preserved" link would be dead. Create one with
// "go run ./cmd/sitegen -snapshot v0.1" when releasing a version.
func TestPreservedBuildsExist(t *testing.T) {
	t.Parallel()
	d, err := loadSiteData(os.DirFS("../../site"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range d.Versions {
		for _, f := range []string{"index.html", "assets/blue-bolt.css", "versions.html"} {
			if _, err := os.Stat("../../docs/" + v.Path + f); err != nil {
				t.Errorf("version %s: missing preserved file %s%s", v.Version, v.Path, f)
			}
		}
	}
}

// A preserved copy is served from a sub-folder, so links to the latest site and
// to other versions need a "../" prefix. Without it they point at
// docs/v0.2/v0.2/index.html and similar places that do not exist.
func TestPreservedCopyLinksResolve(t *testing.T) {
	t.Parallel()
	latest, err := build("../../site", "")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := build("../../site", "../")
	if err != nil {
		t.Fatal(err)
	}
	d := latest.data
	for name, b := range snap.files {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		for _, m := range refRE.FindAllSubmatch(b, -1) {
			ref := string(m[1])
			if strings.Contains(ref, "://") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "#") {
				continue
			}
			target, _, _ := strings.Cut(ref, "#")
			if rest, up := strings.CutPrefix(target, "../"); up {
				// Back at the site root: either a page of the latest site or another version's folder.
				ok := false
				if _, found := latest.files[rest]; found {
					ok = true
				}
				for _, v := range d.Versions {
					ok = ok || strings.HasPrefix(rest, v.Path)
				}
				if !ok {
					t.Errorf("%s: %q does not point at the latest site or a version folder", name, ref)
				}
				continue
			}
			if _, found := snap.files[path.Clean(target)]; !found {
				t.Errorf("%s: broken link %q inside the preserved copy", name, ref)
			}
		}
	}
	// And no link inside a preserved copy may point at a version folder without "../".
	page := string(snap.files["versions.html"])
	for _, v := range d.Versions {
		if strings.Contains(page, `href="`+v.Path) {
			t.Errorf("versions.html links to %q without the ../ prefix", v.Path)
		}
	}
}
