//go:build linux

package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseOptionsExec(t *testing.T) {
	opts, err := parseOptions([]string{"exec", "--cmd", "id", "--target", "/usr/bin/python3", "--timeout", "5s"})
	if err != nil {
		t.Fatalf("parseOptions returned error: %v", err)
	}
	if opts.Mode != "exec" || opts.Cmd != "id" || opts.Target != "/usr/bin/python3" || opts.Timeout != 5*time.Second {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

func TestParseOptionsRestartTarget(t *testing.T) {
	opts, err := parseOptions([]string{"restart", "--cmd", "id", "--restart-target", "/bin/sh"})
	if err != nil {
		t.Fatalf("parseOptions returned error: %v", err)
	}
	if opts.RestartTarget != "/bin/sh" {
		t.Fatalf("restart target = %q", opts.RestartTarget)
	}
}

func TestValidateOptionsAllowsRestartPreflightWithoutCommand(t *testing.T) {
	opts := defaultOptions()
	opts.Mode = "restart"
	opts.Preflight = true
	if err := validateOptions(opts); err != nil {
		t.Fatalf("validateOptions returned error: %v", err)
	}
}

func TestValidateOptionsRejectsExecPreflight(t *testing.T) {
	opts := defaultOptions()
	opts.Mode = "exec"
	opts.Cmd = "id"
	opts.Preflight = true
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "--preflight") {
		t.Fatalf("expected preflight error, got %v", err)
	}
}

func TestParseOptionsRejectsInvalidPID(t *testing.T) {
	_, err := parseOptions([]string{"restart", "--cmd", "id", "--pid", "abc"})
	if err == nil || !strings.Contains(err.Error(), "invalid --pid") {
		t.Fatalf("expected invalid pid error, got %v", err)
	}
}

func TestParseOptionsRejectsInvalidTimeout(t *testing.T) {
	_, err := parseOptions([]string{"exec", "--cmd", "id", "--timeout", "soon"})
	if err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("expected invalid timeout error, got %v", err)
	}
}

func TestValidateOptionsRejectsRelativeRestartTarget(t *testing.T) {
	opts := defaultOptions()
	opts.Mode = "restart"
	opts.Cmd = "id"
	opts.RestartTarget = "bin/sh"
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "--restart-target") {
		t.Fatalf("expected restart target error, got %v", err)
	}
}
