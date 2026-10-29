package main

import (
	"fmt"
	"os"
	"strings"
)

// Marker comments in README.md. Everything between a start and end marker is
// owned by sitegen and rewritten on every run.
const (
	versionsStart = "<!-- versions:start -->"
	versionsEnd   = "<!-- versions:end -->"
	pagesStart    = "<!-- pages:start -->"
	pagesEnd      = "<!-- pages:end -->"
)

// renderReadme returns the README with its generated tables rewritten from the
// site's version list and page metadata. It does not write anything.
func renderReadme(path string, d siteData, pages []pageMeta, base string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the README path is a flag chosen by the maintainer
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	out, err := replaceBetween(string(raw), versionsStart, versionsEnd, versionsTable(d, base))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	out, err = replaceBetween(out, pagesStart, pagesEnd, pagesTable(pages, base))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func replaceBetween(text, start, end, body string) (string, error) {
	i := strings.Index(text, start)
	j := strings.Index(text, end)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("missing %s ... %s markers", start, end)
	}
	return text[:i+len(start)] + "\n" + body + text[j:], nil
}

// versionsTable lists every released site version, newest first as written in
// versions.json, each with a link to its preserved build.
func versionsTable(d siteData, base string) string {
	var b strings.Builder
	b.WriteString("| Version | Released | What it covers | 🔗 Latest | 📌 Preserved |\n|---|---|---|---|---|\n")
	for _, v := range d.Versions {
		label := fmt.Sprintf("**%s** · %s", v.Version, v.Name)
		latest := "—"
		if v.Current {
			label += " ⭐ *current*"
			latest = fmt.Sprintf("[Open](%s)", base)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | [`/%s`](%s%sindex.html) |\n",
			label, v.Date, v.Summary, latest, v.Path, base, v.Path)
	}
	return b.String()
}

// pagesTable lists every page of the current site version.
func pagesTable(pages []pageMeta, base string) string {
	var b strings.Builder
	b.WriteString("| | Page | Source |\n|---|---|---|\n")
	for _, p := range pages {
		icon := p.Icon
		if icon == "" {
			icon = "📄"
		}
		url := base + p.Slug
		if p.Slug == "index.html" {
			url = base
		}
		title := p.Nav
		if title == "" {
			title = p.Title
		}
		fmt.Fprintf(&b, "| %s | [%s](%s) | [`site/pages/%s`](site/pages/%s) |\n", icon, title, url, p.Slug, p.Slug)
	}
	return b.String()
}
