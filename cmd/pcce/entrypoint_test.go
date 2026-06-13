//go:build linux

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestResolveEntrypointPathUsesAbsoluteArgv0(t *testing.T) {
	got, warnings, err := resolveEntrypointPath(1, "/usr/bin/python3", fakeEval(map[string]string{
		"/usr/bin/python3": "/usr/bin/python3.14",
	}))
	if err != nil {
		t.Fatalf("resolveEntrypointPath returned error: %v", err)
	}
	if got != "/usr/bin/python3.14" {
		t.Fatalf("entrypoint = %q", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestResolveEntrypointPathUsesProcExeForRelativeArgv0(t *testing.T) {
	got, warnings, err := resolveEntrypointPath(1, "python3", fakeEval(map[string]string{
		"/proc/1/exe": "/usr/local/bin/python3.14",
	}))
	if err != nil {
		t.Fatalf("resolveEntrypointPath returned error: %v", err)
	}
	if got != "/usr/local/bin/python3.14" {
		t.Fatalf("entrypoint = %q", got)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "not absolute") {
		t.Fatalf("expected non-absolute argv0 warning, got %v", warnings)
	}
}

func TestResolveEntrypointPathDoesNotFallbackToBinSh(t *testing.T) {
	_, warnings, err := resolveEntrypointPath(1, "python3", fakeEval(nil))
	if err == nil {
		t.Fatalf("expected error")
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "/bin/sh") {
			t.Fatalf("unexpected /bin/sh fallback warning: %v", warnings)
		}
	}
}

func fakeEval(values map[string]string) func(string) (string, error) {
	return func(path string) (string, error) {
		if value, ok := values[path]; ok {
			return value, nil
		}
		return "", fmt.Errorf("not found: %s", path)
	}
}
