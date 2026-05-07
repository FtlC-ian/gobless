//go:build production

package main

import (
	"fmt"
	"os"
)

func runSign(_ []string) {
	fmt.Fprintln(os.Stderr, "gobless sign: not available in production build")
	os.Exit(2)
}

func runCAPubKey(_ []string) {
	fmt.Fprintln(os.Stderr, "gobless ca-pubkey: not available in production build")
	os.Exit(2)
}

func runVersion() {
	fmt.Println("gobless production")
}
