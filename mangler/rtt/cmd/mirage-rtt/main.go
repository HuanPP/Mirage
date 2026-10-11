package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"mirage/rtt/internal/config"
	"mirage/rtt/internal/shaper"
	"os"
	"os/signal"
	"syscall"
)

const version = "0.1.0"

func main() {
	if e := execute(os.Args[1:]); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func execute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mirage-rtt {run|install|uninstall|check|version} [-c config] [--install-qdisc] [--dry-run]")
	}
	if args[0] == "version" {
		fmt.Println("mirage-rtt " + version)
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := f.String("c", "/etc/mirage/mangler.yaml", "Shared YAML config")
	var o shaper.Options
	f.StringVar(&o.StateDir, "state-dir", "/var/lib/mirage", "Installer state and rtt-rollback.sh directory")
	f.StringVar(&o.PinDir, "pin-dir", "/sys/fs/bpf/mirage-rtt", "BPF pin directory")
	f.StringVar(&o.Samples, "samples", "", "Optional ACK scheduling telemetry JSONL path")
	// default_qdisc is global and hidden by Linux in a non-initial netns. Labs
	// may supply a read-only snapshot taken in the initial namespace beforehand.
	f.StringVar(&o.DefaultQdiscFile, "default-qdisc-file", "/proc/sys/net/core/default_qdisc", "Kernel default_qdisc sysctl or a trusted initial-netns snapshot")
	f.BoolVar(&o.InstallQdisc, "install-qdisc", false, "Authorize recorded qdisc changes")
	f.BoolVar(&o.DryRun, "dry-run", false, "Print installation/rollback plan without mutation")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	switch args[0] {
	case "install":
		return shaper.Install(c, o)
	case "uninstall":
		return shaper.Uninstall(c, o)
	case "check":
		return shaper.Check(c, o)
	case "run":
		if o.DryRun {
			return shaper.Install(c, o)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return shaper.Run(ctx, c, o)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
