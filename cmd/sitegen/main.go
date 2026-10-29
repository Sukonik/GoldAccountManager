// Command sitegen builds the GoldAccountManager documentation site.
//
// Pages live in site/pages as HTML fragments that start with a metadata
// comment:
//
//	<!--meta title="Packets" nav="Packets" order="2" desc="One sentence."-->
//
// Each fragment is rendered inside site/layout.html and written to docs/, the
// folder GitHub Pages serves. Fragments are Go templates and may call
// {{file "examples/x.gold"}} to include an escaped file from site/.
//
// Run "go run ./cmd/sitegen" to build, or "go run ./cmd/sitegen -check" to
// fail when docs/ or the generated README tables are out of date (used in CI).
//
// The version and page tables in README.md sit between marker comments and are
// generated from site/versions.json and the page metadata, so the README can
// never drift from the site.
//
// To publish a new site version, run
//
//	go run ./cmd/sitegen release -version 0.2.0 -name "Short name" -summary "One sentence."
//
// which records the version, rebuilds the site, writes a preserved copy under
// docs/v0.2/ and updates the README, all in one step.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "release" {
		if err := releaseMain(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "sitegen release:", err)
			os.Exit(1)
		}
		return
	}
	var o options
	flag.StringVar(&o.Src, "src", "site", "site source directory")
	flag.StringVar(&o.Out, "out", "docs", "output directory served by GitHub Pages")
	flag.StringVar(&o.Readme, "readme", "README.md", "README whose generated tables are updated (empty to skip)")
	flag.StringVar(&o.Base, "base", defaultBase, "public address of the site, used for README links")
	flag.BoolVar(&o.Check, "check", false, "do not write; fail if the output or README is out of date")
	flag.StringVar(&o.Snapshot, "snapshot", "", "also write a preserved copy of this build under out/NAME, for example v0.1")
	flag.Parse()
	if err := run(o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
}

// defaultBase is where GitHub Pages serves the site for this repository.
const defaultBase = "https://sukonik.github.io/GoldAccountManager/"

// options configure one sitegen run.
type options struct {
	Src      string // site sources
	Out      string // output folder served by Pages
	Readme   string // README to update; empty skips it
	Base     string // public site address, ending in a slash
	Snapshot string // optional preserved-copy folder name
	Check    bool   // verify instead of writing
}

// built is the result of rendering the site in memory.
type built struct {
	files map[string][]byte
	data  siteData
	pages []pageMeta
}

type navItem struct {
	Label   string
	Href    string
	Current bool
}

type pageMeta struct {
	Slug        string
	Title       string
	Nav         string
	Order       int
	Description string
	Icon        string
}

type pageData struct {
	Title       string
	Description string
	Version     string
	Nav         []navItem
	Content     template.HTML
}

// versionInfo is one released version of the site, from site/versions.json.
type versionInfo struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Date    string `json:"date"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
	Current bool   `json:"-"`
}

// siteData is what page fragments can use: {{.Version}} and {{range .Versions}}.
type siteData struct {
	Version  string
	Versions []versionInfo
	// Root is the path from the page being built back to the site root: ""
	// for the latest site, "../" inside a preserved copy such as docs/v0.2/.
	// Links to other versions and to the latest site are written with it.
	Root string
}

func loadSiteData(srcFS fs.FS) (siteData, error) {
	var d siteData
	v, err := fs.ReadFile(srcFS, "VERSION")
	if err != nil {
		return d, err
	}
	d.Version = strings.TrimSpace(string(v))
	raw, err := fs.ReadFile(srcFS, "versions.json")
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(raw, &d.Versions); err != nil {
		return d, fmt.Errorf("versions.json: %w", err)
	}
	found := false
	for i := range d.Versions {
		d.Versions[i].Current = d.Versions[i].Version == d.Version
		found = found || d.Versions[i].Current
	}
	if !found {
		return d, fmt.Errorf("VERSION %q is not listed in versions.json", d.Version)
	}
	return d, nil
}

var (
	metaRE = regexp.MustCompile(`^\s*<!--meta\s+(.*?)-->`)
	attrRE = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

func parseMeta(slug string, body []byte) (pageMeta, error) {
	m := metaRE.FindSubmatch(body)
	if m == nil {
		return pageMeta{}, fmt.Errorf("%s: missing <!--meta ...--> comment on the first line", slug)
	}
	meta := pageMeta{Slug: slug, Order: 100}
	for _, kv := range attrRE.FindAllSubmatch(m[1], -1) {
		val := string(kv[2])
		switch string(kv[1]) {
		case "title":
			meta.Title = val
		case "nav":
			meta.Nav = val
		case "desc":
			meta.Description = val
		case "icon":
			meta.Icon = val
		case "order":
			n, err := strconv.Atoi(val)
			if err != nil {
				return meta, fmt.Errorf("%s: order must be a number", slug)
			}
			meta.Order = n
		}
	}
	if meta.Title == "" || meta.Description == "" {
		return meta, fmt.Errorf("%s: meta needs title and desc", slug)
	}
	return meta, nil
}

// build renders every page and collects the static assets, returning a map
// from output path (relative to the output directory) to file content.
func build(src, root string) (*built, error) {
	srcFS := os.DirFS(src)
	layoutBytes, err := fs.ReadFile(srcFS, "layout.html")
	if err != nil {
		return nil, err
	}
	layout, err := template.New("layout").Parse(string(layoutBytes))
	if err != nil {
		return nil, fmt.Errorf("layout.html: %w", err)
	}

	data, err := loadSiteData(srcFS)
	if err != nil {
		return nil, err
	}
	data.Root = root

	funcs := template.FuncMap{
		"file": func(name string) (string, error) {
			b, err := fs.ReadFile(srcFS, name)
			return string(b), err
		},
	}

	entries, err := fs.Glob(srcFS, "pages/*.html")
	if err != nil {
		return nil, err
	}
	type page struct {
		meta pageMeta
		body []byte
	}
	var pages []page
	for _, e := range entries {
		body, err := fs.ReadFile(srcFS, e)
		if err != nil {
			return nil, err
		}
		slug := filepath.Base(e)
		meta, err := parseMeta(slug, body)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page{meta, body})
	}
	sort.SliceStable(pages, func(i, j int) bool {
		if pages[i].meta.Order != pages[j].meta.Order {
			return pages[i].meta.Order < pages[j].meta.Order
		}
		return pages[i].meta.Slug < pages[j].meta.Slug
	})

	files := map[string][]byte{}
	for _, p := range pages {
		tpl, err := template.New(p.meta.Slug).Funcs(funcs).Parse(string(metaRE.ReplaceAll(p.body, nil)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.meta.Slug, err)
		}
		var content bytes.Buffer
		if err := tpl.Execute(&content, data); err != nil {
			return nil, fmt.Errorf("%s: %w", p.meta.Slug, err)
		}
		var nav []navItem
		for _, q := range pages {
			if q.meta.Nav != "" {
				nav = append(nav, navItem{Label: q.meta.Nav, Href: q.meta.Slug, Current: q.meta.Slug == p.meta.Slug})
			}
		}
		var page bytes.Buffer
		pd := pageData{Title: p.meta.Title, Description: p.meta.Description, Version: data.Version, Nav: nav, Content: template.HTML(content.String())} //nolint:gosec // page fragments are authored in this repo
		if err := layout.Execute(&page, pd); err != nil {
			return nil, fmt.Errorf("%s: %w", p.meta.Slug, err)
		}
		files[p.meta.Slug] = page.Bytes()
	}

	err = fs.WalkDir(srcFS, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(srcFS, path)
		files[path] = b
		return err
	})
	if err != nil {
		return nil, err
	}
	// Example packets are published next to the pages so the demo can open them.
	err = fs.WalkDir(srcFS, "examples", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(srcFS, path)
		files[path] = b
		return err
	})
	if err != nil {
		return nil, err
	}
	files["favicon.svg"] = files["assets/favicon.svg"]
	files[".nojekyll"] = nil // serve files as they are, no Jekyll processing

	metas := make([]pageMeta, 0, len(pages))
	for _, p := range pages {
		metas = append(metas, p.meta)
	}
	return &built{files: files, data: data, pages: metas}, nil
}

func run(o options, log io.Writer) error {
	b, err := build(o.Src, "")
	if err != nil {
		return err
	}
	var readme string
	if o.Readme != "" {
		if readme, err = renderReadme(o.Readme, b.data, b.pages, o.Base); err != nil {
			return err
		}
	}
	if o.Check {
		return check(b, readme, o)
	}
	targets := []struct {
		dir   string
		files map[string][]byte
	}{{o.Out, b.files}}
	if o.Snapshot != "" {
		if filepath.Base(o.Snapshot) != o.Snapshot || strings.HasPrefix(o.Snapshot, ".") {
			return fmt.Errorf("snapshot name %q must be a single folder name like v0.1", o.Snapshot)
		}
		// A preserved copy lives one folder down, so its links back to the
		// site root and to other versions are built with a "../" prefix.
		snap, err := build(o.Src, "../")
		if err != nil {
			return err
		}
		targets = append(targets, struct {
			dir   string
			files map[string][]byte
		}{filepath.Join(o.Out, o.Snapshot), snap.files})
	}
	for _, t := range targets {
		if err := write(t.files, t.dir); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(log, "wrote %d files to %s\n", len(t.files), t.dir); err != nil {
			return err
		}
	}
	if o.Readme != "" {
		if err := os.WriteFile(o.Readme, []byte(readme), 0o644); err != nil { //nolint:gosec // the README is a public file
			return err
		}
		if _, err := fmt.Fprintf(log, "updated %s\n", o.Readme); err != nil {
			return err
		}
	}
	return nil
}

// check reports every generated file, and the README, that is missing or
// differs from what a build would write.
func check(b *built, readme string, o options) error {
	problems := verify(b.files, o.Out)
	if o.Readme != "" {
		got, err := os.ReadFile(o.Readme)
		if err != nil || string(got) != readme {
			problems = append(problems, o.Readme+": generated tables are out of date")
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return fmt.Errorf("generated files are out of date, run \"go run ./cmd/sitegen\":\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func write(files map[string][]byte, dir string) error {
	for name, b := range files {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil { //nolint:gosec // published site files are meant to be world-readable
			return err
		}
	}
	return nil
}

// verify returns a problem line for every generated file that is missing or
// different on disk.
func verify(files map[string][]byte, out string) []string {
	var problems []string
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // paths come from the generator's own output list
		switch {
		case err != nil:
			problems = append(problems, name+": missing")
		case !bytes.Equal(got, want):
			problems = append(problems, name+": out of date")
		}
	}
	return problems
}
