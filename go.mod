module github.com/sukonik/goldaccountmanager

go 1.24

// The confirmation server is a network service, and govulncheck reports many
// standard-library vulnerabilities in code it runs on older Go releases (39 on
// Go 1.24.7, 10 on 1.25.13, 1 on 1.26.9, none on 1.26.10 at the time of
// writing). This line makes "go build" fetch a patched toolchain automatically.
// Raise it when govulncheck reports something fixed in a newer patch release.
// Importing the packet or verify packages does not require this toolchain.
toolchain go1.26.10
