//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnifiedCgroupPath(t *testing.T) {
	data := []byte("0::/kubepods.slice/pod123\n")
	if got := unifiedCgroupPath(data); got != "/kubepods.slice/pod123" {
		t.Fatalf("unifiedCgroupPath = %q", got)
	}
}

func TestUnifiedCgroupKillPath(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	cgroupRoot := filepath.Join(root, "cgroup")
	pidDir := filepath.Join(procRoot, "42")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/demo\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, ok := unifiedCgroupKillPath(procRoot, cgroupRoot, 42)
	if !ok {
		t.Fatalf("expected cgroup.kill path")
	}
	want := filepath.Join(cgroupRoot, "/demo", "cgroup.kill")
	if got != want {
		t.Fatalf("kill path = %q, want %q", got, want)
	}
}

func TestParseProcPID(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"1", true},
		{"123", true},
		{"", false},
		{"abc", false},
		{"12x", false},
		{"0", false},
	}
	for _, tt := range tests {
		_, ok := parseProcPID(tt.name)
		if ok != tt.ok {
			t.Fatalf("parseProcPID(%q) ok = %v, want %v", tt.name, ok, tt.ok)
		}
	}
}

func TestDefaultCrashMethodsPreferSIGINTBeforeSIGKILL(t *testing.T) {
	methods := defaultCrashMethods()
	if len(methods) < 3 {
		t.Fatalf("unexpected crash methods: %v", methods)
	}
	if methods[1] != crashSigint || methods[2] != crashSigkill {
		t.Fatalf("crash method order = %v, want SIGINT before SIGKILL", methods)
	}
}

func TestSignalMaskFieldAndSIGINTDetection(t *testing.T) {
	status := []byte("Name:\tpython3\nSigIgn:\t0000000001001000\nSigCgt:\t0000000000000002\n")
	caught, ok := signalMaskField(status, "SigCgt")
	if !ok {
		t.Fatalf("SigCgt not parsed")
	}
	bit := uint64(1) << uint(syscall.SIGINT-1)
	if caught&bit == 0 {
		t.Fatalf("SIGINT bit not set in SigCgt mask %#x", caught)
	}
	ignored, ok := signalMaskField(status, "SigIgn")
	if !ok {
		t.Fatalf("SigIgn not parsed")
	}
	if ignored&bit != 0 {
		t.Fatalf("SIGINT should not be ignored in mask %#x", ignored)
	}
}
