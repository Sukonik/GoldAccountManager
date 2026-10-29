package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var semverRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

type semver [3]int

func parseSemver(s string) (semver, error) {
	m := semverRE.FindStringSubmatch(s)
	if m == nil {
		return semver{}, fmt.Errorf("version %q must look like 1.2.3", s)
	}
	var v semver
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, nil
}

func (a semver) less(b semver) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// previewPath returns the folder a version is preserved under: v0.2/ for
// 0.2.0, and v0.2.1/ for a patch release so it cannot collide with 0.2.0.
func previewPath(v semver) string {
	if v[2] == 0 {
		return fmt.Sprintf("v%d.%d/", v[0], v[1])
	}
	return fmt.Sprintf("v%d.%d.%d/", v[0], v[1], v[2])
}

// releaseOptions describe one release.
type releaseOptions struct {
	options
	Version string
	Name    string
	Summary string
	Date    string
}

func releaseMain(args []string, log io.Writer) error {
	var r releaseOptions
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	fs.StringVar(&r.Version, "version", "", "new version, like 0.2.0 (required)")
	fs.StringVar(&r.Name, "name", "", "short name of the release (required)")
	fs.StringVar(&r.Summary, "summary", "", "one sentence on what it covers (required)")
	fs.StringVar(&r.Date, "date", time.Now().UTC().Format(time.DateOnly), "release date, YYYY-MM-DD")
	fs.StringVar(&r.Src, "src", "site", "site source directory")
	fs.StringVar(&r.Out, "out", "docs", "output directory served by GitHub Pages")
	fs.StringVar(&r.Readme, "readme", "README.md", "README to update")
	fs.StringVar(&r.Base, "base", defaultBase, "public address of the site")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return release(r, log)
}

// release records a new site version, rebuilds the site, writes a preserved
// copy and updates the README. If anything fails, versions.json and VERSION
// are put back as they were.
func release(r releaseOptions, log io.Writer) (err error) {
	ver, err := parseSemver(r.Version)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Summary) == "" {
		return errors.New("-name and -summary are required")
	}
	if _, perr := time.Parse(time.DateOnly, r.Date); perr != nil {
		return fmt.Errorf("date %q must look like 2026-10-29", r.Date)
	}

	versionsFile := filepath.Join(r.Src, "versions.json")
	versionFile := filepath.Join(r.Src, "VERSION")
	oldVersions, err := os.ReadFile(versionsFile) //nolint:gosec // site source path chosen by the maintainer
	if err != nil {
		return err
	}
	oldVersion, err := os.ReadFile(versionFile) //nolint:gosec // site source path chosen by the maintainer
	if err != nil {
		return err
	}
	var list []versionInfo
	if err := json.Unmarshal(oldVersions, &list); err != nil {
		return fmt.Errorf("versions.json: %w", err)
	}

	path := previewPath(ver)
	for _, v := range list {
		have, perr := parseSemver(v.Version)
		if perr != nil {
			return fmt.Errorf("versions.json: %w", perr)
		}
		if v.Version == r.Version {
			return fmt.Errorf("version %s already exists", r.Version)
		}
		if !have.less(ver) {
			return fmt.Errorf("version %s is not newer than %s", r.Version, v.Version)
		}
		if v.Path == path {
			return fmt.Errorf("preserved folder %s is already used by version %s", path, v.Version)
		}
	}
	if _, serr := os.Stat(filepath.Join(r.Out, path)); serr == nil {
		return fmt.Errorf("%s already exists: preserved builds are never overwritten", filepath.Join(r.Out, path))
	}

	list = append([]versionInfo{{Version: r.Version, Name: r.Name, Date: r.Date, Path: path, Summary: r.Summary}}, list...)
	encoded, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = os.WriteFile(versionsFile, oldVersions, 0o644) //nolint:gosec // restoring a tracked source file
			_ = os.WriteFile(versionFile, oldVersion, 0o644)   //nolint:gosec // restoring a tracked source file
		}
	}()
	if err = os.WriteFile(versionsFile, append(encoded, '\n'), 0o644); err != nil { //nolint:gosec // tracked source file
		return err
	}
	if err = os.WriteFile(versionFile, []byte(r.Version+"\n"), 0o644); err != nil { //nolint:gosec // tracked source file
		return err
	}

	o := r.options
	o.Snapshot = strings.TrimSuffix(path, "/")
	if err = run(o, log); err != nil {
		return err
	}
	_, err = fmt.Fprintf(log, "released %s: latest site and preserved copy at %s%s\n", r.Version, o.Out+"/", path)
	return err
}
