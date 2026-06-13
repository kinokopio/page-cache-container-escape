//go:build linux

package main

import (
	"fmt"
	"os"
)

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err == nil {
		err = validateOptions(opts)
	}
	if err == nil {
		err = run(opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n\n", err)
		usage()
		os.Exit(1)
	}
}
