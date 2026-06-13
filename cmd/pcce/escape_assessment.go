//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

type escapeStatus string

const (
	escapeYes   escapeStatus = "YES"
	escapeMaybe escapeStatus = "MAYBE"
	escapeNo    escapeStatus = "NO"

	escapeModeRestart = "restart"
	escapeModeExec    = "exec-fallback"
	escapeModeNone    = "none"
)

type escapeAssessment struct {
	Status   escapeStatus
	Mode     string
	Reasons  []string
	Warnings []string
}

type preflightVerdictInput struct {
	CopyFailOK     bool
	EntrypointOK   bool
	CrashOK        bool
	CrashUncertain bool
	Linkers        []linkerCandidateReport
	SUID           []suidCandidateReport
}

func assessRestartEscape(pid int, injectorSize int, entrypoint string, copyFailErr error) escapeAssessment {
	a := escapeAssessment{Status: escapeYes, Mode: escapeModeRestart}
	if copyFailErr != nil {
		a.Status = escapeNo
		a.Mode = escapeModeNone
		a.Reasons = append(a.Reasons, fmt.Sprintf("Copy Fail is unavailable or inconclusive: %v", copyFailErr))
		return a
	}

	if err := validateShebangTarget(entrypoint); err != nil {
		a.Reasons = append(a.Reasons, fmt.Sprintf("entrypoint cannot be patched: %v", err))
	}

	linkers := inspectLinkerCandidates(injectorSize)
	switch linkerEscapeStatus(linkers) {
	case escapeNo:
		a.Reasons = append(a.Reasons, "no usable dynamic linker and no writable-looking placeholder path")
	case escapeMaybe:
		a.Status = escapeMaybe
		a.Warnings = append(a.Warnings, "dynamic linker is missing; restart depends on creating a placeholder linker at runtime")
	}

	crashReport := inspectCrashTrigger(crashOptions{PID: pid})
	switch {
	case crashReport.CgroupKillOK:
	case crashReport.SIGINTLikelyOK:
		a.Warnings = append(a.Warnings, "cgroup.kill is unavailable, but PID 1 appears to handle SIGINT cleanly")
	default:
		a.Status = minEscapeStatus(a.Status, escapeMaybe)
		a.Warnings = append(a.Warnings, "no clean restart trigger detected; restart depends on less reliable fallback methods")
	}
	if len(a.Reasons) > 0 {
		a.Status = escapeMaybe
		a.Mode = escapeModeExec
	}
	return a
}

func linkerEscapeStatus(reports []linkerCandidateReport) escapeStatus {
	hasMissingWithExistingParent := false
	for _, report := range reports {
		if report.Status == "usable" {
			return escapeYes
		}
		if report.Status == "missing" &&
			!strings.Contains(report.Detail, "not currently accessible") &&
			!strings.Contains(report.Detail, "not a directory") {
			// Existing parent does not prove write permission, so this is MAYBE.
			hasMissingWithExistingParent = true
		}
	}
	if hasMissingWithExistingParent {
		return escapeMaybe
	}
	return escapeNo
}

func minEscapeStatus(current, next escapeStatus) escapeStatus {
	if current == escapeNo || next == escapeNo {
		return escapeNo
	}
	if current == escapeMaybe || next == escapeMaybe {
		return escapeMaybe
	}
	return escapeYes
}

func printEscapeAssessment(a escapeAssessment) {
	fmt.Println("[*] Escape assessment")
	switch a.Status {
	case escapeYes:
		fmt.Printf("    [ESCAPE: YES] mode=%s\n", a.Mode)
	case escapeMaybe:
		fmt.Printf("    [ESCAPE: MAYBE] mode=%s\n", a.Mode)
	default:
		fmt.Printf("    [ESCAPE: NO] mode=%s\n", escapeModeNone)
	}
	for _, reason := range a.Reasons {
		fmt.Printf("    [-] %s\n", reason)
	}
	for _, warning := range a.Warnings {
		fmt.Printf("    [!] %s\n", warning)
	}
	fmt.Println()
}

func printPreflightVerdict(in preflightVerdictInput) error {
	const (
		green = "\033[32m"
		red   = "\033[31m"
		reset = "\033[0m"
	)

	fmt.Println("[*] Preflight verdict")
	fmt.Println("====================")

	if !in.CopyFailOK {
		fmt.Printf("%s[-] ESCAPE: not viable%s\n", red, reset)
		fmt.Println("    Copy Fail primitive is not available on this kernel")
		fmt.Println()
		return fmt.Errorf("preflight: Copy Fail not available")
	}

	linkerExists, linkerMissing := classifyLinkers(in.Linkers)
	hasSUID := hasSUIDCandidate(in.SUID)
	isRoot := os.Geteuid() == 0

	if linkerExists || isRoot || hasSUID {
		if !in.EntrypointOK {
			fmt.Printf("%s[+] ESCAPE: viable (exec only)%s\n", green, reset)
			fmt.Println("    Restart path blocked: entrypoint cannot hold shebang patch")
			fmt.Println()
			return nil
		}

		label := "restart"
		switch {
		case !linkerExists && isRoot:
			label = "restart"
		case !linkerExists && hasSUID:
			label = "restart, privilege escalation required"
		}
		if in.CrashUncertain && !in.CrashOK {
			label += ", crash trigger uncertain"
		}
		fmt.Printf("%s[+] ESCAPE: viable (%s)%s\n", green, label, reset)
		if !linkerExists && isRoot {
			fmt.Println("    Dynamic linker placeholder can be created because current euid is root")
		}
		if !linkerExists && hasSUID {
			fmt.Println("    SUID candidate exists for privilege escalation to create linker placeholder")
		}
		fmt.Println()
		return nil
	}

	if !in.EntrypointOK {
		fmt.Printf("%s[-] ESCAPE: not viable%s\n", red, reset)
		fmt.Println("    No dynamic linker, no root, no SUID candidates, and entrypoint is blocked")
		fmt.Println()
		return fmt.Errorf("preflight: no viable escape path")
	}

	if linkerMissing {
		fmt.Printf("%s[+] ESCAPE: viable (exec only)%s\n", green, reset)
		fmt.Println("    No dynamic linker and no way to create one; use exec mode instead")
		fmt.Println("    pcce exec --cmd '<command>'")
		fmt.Println()
		return nil
	}

	fmt.Printf("%s[-] ESCAPE: not viable%s\n", red, reset)
	fmt.Println("    No usable restart path and no exec fallback was identified")
	fmt.Println()
	return fmt.Errorf("preflight: no viable escape path")
}

func classifyLinkers(reports []linkerCandidateReport) (exists bool, missing bool) {
	for _, r := range reports {
		switch r.Status {
		case "usable":
			exists = true
		case "missing":
			missing = true
		}
	}
	return exists, missing
}

func hasSUIDCandidate(reports []suidCandidateReport) bool {
	for _, r := range reports {
		if r.Status == "candidate" {
			return true
		}
	}
	return false
}
