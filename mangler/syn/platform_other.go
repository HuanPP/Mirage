//go:build !linux

package syn

import (
	"context"
	"fmt"
	"io"
)

func Run(context.Context, Config) error              { return fmt.Errorf("NFQUEUE requires Linux") }
func Check(context.Context, Config, io.Writer) error { return fmt.Errorf("check requires Linux") }
