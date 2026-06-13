//go:build linux

package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
)

func elfInterpreter(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		data, err := io.ReadAll(prog.Open())
		if err != nil {
			return "", fmt.Errorf("read PT_INTERP: %w", err)
		}
		interp := string(bytes.TrimRight(data, "\x00"))
		if interp == "" {
			return "", fmt.Errorf("empty PT_INTERP")
		}
		return interp, nil
	}
	return "", fmt.Errorf("PT_INTERP not found")
}
