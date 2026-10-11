package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	syn "mirage/syn"
)

var version = "0.1.0"

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mirage-syn:", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mirage-syn run|rules print|install|uninstall|check|version [-c config.yaml] [--no-rules]")
	}
	command := args[0]
	args = args[1:]
	if command == "version" {
		fmt.Println("mirage-syn", version)
		return nil
	}
	action := ""
	if command == "rules" {
		if len(args) == 0 {
			return fmt.Errorf("rules requires print, install, or uninstall")
		}
		action, args = args[0], args[1:]
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	path := f.String("c", "/etc/mirage/mangler.yaml", "shared YAML configuration")
	noRules := f.Bool("no-rules", false, "run without installing or removing nft rules")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if command == "rules" && action == "uninstall" {
		return syn.UninstallRules(ctx)
	}
	c, err := syn.LoadConfig(*path)
	if err != nil {
		return err
	}
	c.NoRules = *noRules
	switch command {
	case "run":
		return syn.Run(ctx, c)
	case "check":
		return syn.Check(ctx, c, os.Stdout)
	case "rules":
		switch action {
		case "print":
			b, err := syn.Rules(c)
			if err == nil {
				fmt.Print(b)
			}
			return err
		case "install":
			return syn.InstallRules(ctx, c)
		}
	}
	return fmt.Errorf("unknown command or rules action")
}
