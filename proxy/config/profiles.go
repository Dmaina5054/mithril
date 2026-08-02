package config

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Profile is one entry in profiles.yaml — format per spec section 7
// ("Adding a New IPRoyal Sub-User / Workload"). Password is the base
// IPRoyal sub-user password; internal/proxy.BuildPassword appends the
// per-request geo/session suffix on top of it, it is never sent as-is.
//
// EnforcePIDs is Session B Phase 7's addition: spec's eBPF Feature 1
// says the proxy_required_pids map gets populated "from profiles.yaml"
// but doesn't specify a field for it — this is that field. A PID
// listed here has its outbound connections transparently redirected
// through this profile's routing/credentials, per the eBPF
// cgroup/connect4 hook in ebpf/redirect.
type Profile struct {
	SubuserHash      string   `yaml:"subuser_hash"`
	Username         string   `yaml:"username"`
	Password         string   `yaml:"password"`
	ListenPort       int      `yaml:"listen_port"`
	BandwidthAlertGB float64  `yaml:"bandwidth_alert_gb"`
	EnforcePIDs      []uint32 `yaml:"enforce_pids,omitempty"`
}

type ProfilesConfig struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

// SortedNames returns profile names in a stable, deterministic order.
// Used as the profile index assignment for eBPF Feature 1's
// proxy_required_pids/redirect_targets maps — spec's own example
// ("0=default, 1=kioo-labs") happens to match alphabetical order for
// those two names, which is exactly what this produces.
func (c *ProfilesConfig) SortedNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
