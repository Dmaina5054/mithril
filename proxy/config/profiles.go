package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile is one entry in profiles.yaml — format per spec section 7
// ("Adding a New IPRoyal Sub-User / Workload"). Password is the base
// IPRoyal sub-user password; internal/proxy.BuildPassword appends the
// per-request geo/session suffix on top of it, it is never sent as-is.
type Profile struct {
	SubuserHash      string  `yaml:"subuser_hash"`
	Username         string  `yaml:"username"`
	Password         string  `yaml:"password"`
	ListenPort       int     `yaml:"listen_port"`
	BandwidthAlertGB float64 `yaml:"bandwidth_alert_gb"`
}

type ProfilesConfig struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

func (c *ProfilesConfig) Validate() error {
	if len(c.Profiles) == 0 {
		return fmt.Errorf("profiles: no profiles defined")
	}
	seenPorts := map[int]string{}
	for name, p := range c.Profiles {
		if p.Username == "" {
			return fmt.Errorf("profiles: %s: username is required", name)
		}
		if p.Password == "" {
			return fmt.Errorf("profiles: %s: password is required", name)
		}
		if p.ListenPort <= 0 || p.ListenPort > 65535 {
			return fmt.Errorf("profiles: %s: listen_port %d is not a valid port", name, p.ListenPort)
		}
		if other, ok := seenPorts[p.ListenPort]; ok {
			return fmt.Errorf("profiles: %s and %s both claim listen_port %d", name, other, p.ListenPort)
		}
		seenPorts[p.ListenPort] = name
	}
	return nil
}

func LoadProfilesConfig(path string) (*ProfilesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profiles: read %s: %w", path, err)
	}
	var cfg ProfilesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("profiles: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
