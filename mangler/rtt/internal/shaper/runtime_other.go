//go:build !linux

package shaper

import (
	"context"
	"fmt"
	"mirage/rtt/internal/config"
)

type Options struct {
	StateDir, PinDir, Samples string
	DefaultQdiscFile          string
	InstallQdisc, DryRun      bool
}

func unsupported() error                                { return fmt.Errorf("mirage-rtt requires Linux 6.1 or later") }
func Install(config.Config, Options) error              { return unsupported() }
func Uninstall(config.Config, Options) error            { return unsupported() }
func Check(config.Config, Options) error                { return unsupported() }
func Run(context.Context, config.Config, Options) error { return unsupported() }
