//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPatchInjectorWritesPayloadLengthAndBytes(t *testing.T) {
	payload := []byte("#!/bin/sh\necho ok\n")
	patched, err := patchInjector(payload)
	if err != nil {
		t.Fatalf("patchInjector returned error: %v", err)
	}

	marker := []byte(payloadMarker)
	offset := bytes.Index(patched, marker)
	if offset < 0 {
		t.Fatalf("payload marker not found")
	}
	lenOff := offset + len(marker)
	bufOff := lenOff + 8

	var gotLen uint64
	for i := range 8 {
		gotLen |= uint64(patched[lenOff+i]) << (8 * i)
	}
	if gotLen != uint64(len(payload)) {
		t.Fatalf("payload length = %d, want %d", gotLen, len(payload))
	}
	if !bytes.Equal(patched[bufOff:bufOff+len(payload)], payload) {
		t.Fatalf("payload bytes were not copied into injector")
	}
}

func TestPatchInjectorRejectsOversizedPayload(t *testing.T) {
	_, err := patchInjector(bytes.Repeat([]byte("A"), 4097))
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected oversized payload error, got %v", err)
	}
}
