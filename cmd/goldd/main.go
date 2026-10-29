// Command goldd is the GoldAccountManager command line. In Phase 0 it creates
// and checks packets. The server and demo mode arrive in later phases.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "0.0.0-dev"

const usage = `goldd: GoldAccountManager

Usage:
  goldd version
  goldd packet new   -app ID [-name NAME] [-o FILE]
  goldd packet check [-app ID] FILE

A packet is a plain-JSON account file the user owns. "new" writes an empty one
for an app. "check" validates a file the way an app would when opening it.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		sayln(stdout, "goldd", version)
		return 0
	case "packet":
		if len(args) < 2 {
			say(stderr, usage)
			return 2
		}
		switch args[1] {
		case "new":
			return packetNew(args[2:], stdout, stderr)
		case "check":
			return packetCheck(args[2:], stdout, stderr)
		}
	case "help", "-h", "--help":
		say(stdout, usage)
		return 0
	}
	say(stderr, usage)
	return 2
}

func packetNew(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packet new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	app := fs.String("app", "", "app id (required): lowercase letters, digits, hyphens")
	name := fs.String("name", "My account", "display name")
	out := fs.String("o", "", "write to this file instead of standard output")
	if fs.Parse(args) != nil {
		return 2
	}
	p, err := packet.New(*app, *name, packet.AppInfo{Name: "goldd", Version: version}, time.Now())
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	data, err := p.Marshal()
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	if *out == "" {
		_, _ = stdout.Write(data)
		return 0
	}
	// 0600: a packet is private to its owner.
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	sayf(stdout, "wrote %s (packet %s)\n", *out, p.PacketID)
	return 0
}

func packetCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packet check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	app := fs.String("app", "", "require the packet to belong to this app id")
	if fs.Parse(args) != nil || fs.NArg() != 1 {
		say(stderr, usage)
		return 2
	}
	data, err := os.ReadFile(fs.Arg(0)) //nolint:gosec // the user names the file to check
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	p, warns, err := packet.Parse(data, packet.ParseOptions{ExpectAppID: *app})
	if err != nil {
		sayln(stderr, "rejected:", err)
		return 1
	}
	sayf(stdout, "ok  %s  app=%s  revision=%s  saved=%s  attestations=%d\n",
		p.PacketID, p.AppID, p.RevisionID, p.SavedAt, len(p.Attestations))
	for _, w := range warns {
		sayf(stdout, "warning: %s: %s\n", w.Code, w.Message)
	}
	if len(warns) > 0 {
		return 3
	}
	return 0
}

// say, sayln and sayf write command output. A failed write to the terminal
// has no useful recovery in a CLI, so the error is dropped on purpose.
func say(w io.Writer, s string)                 { _, _ = io.WriteString(w, s) }
func sayln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }
func sayf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
