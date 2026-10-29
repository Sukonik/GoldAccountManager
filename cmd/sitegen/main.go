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
// fail when docs/ is out of date (used in CI).
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
	src := flag.String("src", "site", "site source directory")
	out := flag.String("out", "docs", "output directory served by GitHub Pages")
	check := flag.Bool("check", false, "do not write; fail if the output is out of date")
	snapshot := flag.String("snapshot", "", "also write a preserved copy of this build under out/NAME, for example v0.1")
	flag.Parse()
	if err := run(*src, *out, *snapshot, *check, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
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
func build(src string) (map[string][]byte, error) {
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
	files["favicon.svg"] = files["assets/favicon.svg"]
	files[".nojekyll"] = nil // serve files as they are, no Jekyll processing
	return files, nil
}

func run(src, out, snapshot string, check bool, log io.Writer) error {
	files, err := build(src)
	if err != nil {
		return err
	}
	if check {
		return verify(files, out)
	}
	dirs := []string{out}
	if snapshot != "" {
		if filepath.Base(snapshot) != snapshot || strings.HasPrefix(snapshot, ".") {
			return fmt.Errorf("snapshot name %q must be a single folder name like v0.1", snapshot)
		}
		dirs = append(dirs, filepath.Join(out, snapshot))
	}
	for _, dir := range dirs {
		if err := write(files, dir); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(log, "wrote %d files to %s\n", len(files), dir); err != nil {
			return err
		}
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

// verify reports every generated file that is missing or different on disk.
func verify(files map[string][]byte, out string) error {
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
	slices.Sort(problems)
	if len(problems) > 0 {
		return fmt.Errorf("%s is out of date, run \"go run ./cmd/sitegen\":\n  %s", out, strings.Join(problems, "\n  "))
	}
	return nil
}
