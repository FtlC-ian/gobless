//go:build !production

package main

import (
	"fmt"
	"os"

	"github.com/FtlC-ian/gobless/internal/cli"
)

func runSign(args []string) {
	if err := cli.RunSign(args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gobless sign: %v\n", err)
		os.Exit(1)
	}
}

func runCAPubKey(args []string) {
	if err := cli.RunCAPubKey(args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gobless ca-pubkey: %v\n", err)
		os.Exit(1)
	}
}

func runVersion() {
	cli.RunVersion(os.Stdout)
}
