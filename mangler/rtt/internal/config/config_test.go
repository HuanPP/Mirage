package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("mark: 0x4d49\nsyn:\n  enabled: true\nrtt:\n  base_delay_ms: 160\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, e := Load(p)
	if e != nil || c.Mark != 0x4d49 || c.Base() != 160 {
		t.Fatalf("%+v %v", c, e)
	}
	if err := os.WriteFile(p, []byte("rtt:\n  max_delay_ms: 10000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, e = Load(p); e == nil {
		t.Fatal("unsafe horizon accepted")
	}
}
