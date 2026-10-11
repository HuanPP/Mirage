package syn

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type SynConfig struct {
	Enabled  bool   `yaml:"enabled"`
	QueueNum uint16 `yaml:"queue_num"`
	Profile  string `yaml:"profile"`
	MSS      uint16 `yaml:"mss"`
}

// Config reads only the common keys and the syn section. Other YAML keys are ignored.
type Config struct {
	Mark    uint32    `yaml:"mark"`
	IPv6    string    `yaml:"ipv6"`
	SYN     SynConfig `yaml:"syn"`
	NoRules bool      `yaml:"-"`
}

func DefaultConfig() Config {
	return Config{Mark: 0x4d49, IPv6: "block", SYN: SynConfig{true, 4949, "macos", 1460}}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Mark == 0 {
		return fmt.Errorf("mark must be nonzero to isolate shaped traffic")
	}
	if c.IPv6 != "block" && c.IPv6 != "passthrough" {
		return fmt.Errorf("ipv6 must be block or passthrough")
	}
	if c.SYN.Profile != "macos" || c.SYN.MSS == 0 {
		return fmt.Errorf("syn.profile must be macos and syn.mss must be nonzero")
	}
	return nil
}
