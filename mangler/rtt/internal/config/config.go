package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"math"
	"os"
	"strconv"
)

type Config struct {
	Mark uint32 `yaml:"mark"`
	RTT  struct {
		Enabled bool    `yaml:"enabled"`
		Iface   string  `yaml:"iface"`
		Base    string  `yaml:"base_delay_ms"`
		Default float64 `yaml:"default_delay_ms"`
		Jitter  float64 `yaml:"jitter_ms"`
		Rho     float64 `yaml:"jitter_rho"`
		Min     float64 `yaml:"min_delay_ms"`
		Max     float64 `yaml:"max_delay_ms"`
		Client  struct {
			Port uint16 `yaml:"inbound_port"`
		} `yaml:"client"`
	} `yaml:"rtt"`
}

func Load(path string) (Config, error) {
	var c Config
	c.Mark = 0x4d49
	c.RTT.Enabled = true
	c.RTT.Iface = "ens4"
	c.RTT.Base = "auto"
	c.RTT.Default = 160
	c.RTT.Jitter = 8
	c.RTT.Rho = .9
	c.RTT.Max = 600
	c.RTT.Client.Port = 443
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Mark == 0 || c.RTT.Iface == "" || c.RTT.Client.Port == 0 {
		return c, fmt.Errorf("mark, iface and inbound_port must be nonzero")
	}
	for _, v := range []float64{c.RTT.Default, c.RTT.Jitter, c.RTT.Rho, c.RTT.Min, c.RTT.Max} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return c, fmt.Errorf("non-finite config value")
		}
	}
	if c.RTT.Min < 0 || c.RTT.Max > 600 || c.RTT.Min > c.RTT.Max || c.RTT.Jitter < 0 || c.RTT.Jitter > 200 || c.RTT.Rho < 0 || c.RTT.Rho >= 1 || c.RTT.Default < c.RTT.Min || c.RTT.Default > c.RTT.Max {
		return c, fmt.Errorf("invalid delay or jitter bounds (maximum delay 600ms)")
	}
	if c.RTT.Base != "auto" {
		v, e := strconv.ParseFloat(c.RTT.Base, 64)
		if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < c.RTT.Min || v > c.RTT.Max {
			return c, fmt.Errorf("invalid base_delay_ms")
		}
	}
	return c, nil
}
func (c Config) Base() float64 {
	if c.RTT.Base == "auto" {
		return c.RTT.Default
	}
	v, _ := strconv.ParseFloat(c.RTT.Base, 64)
	return v
}
