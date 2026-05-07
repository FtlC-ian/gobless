//go:build !production

// Package cli provides the GoBless CLI subcommand implementations.
package cli

import (
	"fmt"
	"io"
)

// Version is the current GoBless version string.
const Version = "dev"

// RunVersion writes the version string to stdout.
func RunVersion(stdout io.Writer) {
	fmt.Fprintf(stdout, "gobless %s\n", Version)
}
