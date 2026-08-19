package config

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// legacyProvider is the provider name assumed for a profile that omits
// `provider` entirely — every profile written before the
// internal/vpnprovider plugin layer existed. Kept as a literal, not an
// import of internal/vpnprovider/iproyal.Name, so this package (a pure
// config loader — see the package doc comment) doesn't need to depend
// on any specific provider implementation; keep it in sync with that
// constant if it's ever renamed.
const legacyProvider = "iproyal"

// Profile is one entry in profiles.yaml — format per spec section 7
// ("Adding a New IPRoyal Sub-User / Workload"), extended by the
// internal/vpnprovider plugin layer with Provider/UpstreamAddr/
// ProviderConfig.
//
// Username/Password/SubuserHash/UpstreamAddr are IPRoyal's own field
// names, kept at the top level for backward compatibility: a profile
// that omits Provider (or sets it to "iproyal" explicitly) and doesn't
// set ProviderConfig gets these four fields synthesized into that
// provider's config by main.go, exactly as if it had written them under
// provider_config itself — see main.go's buildProvider. Password is the
// BASE IPRoyal sub-user password; the iproyal provider appends the
// per-request geo/session suffix on top of it, it is never sent as-is.
//
// Any OTHER provider ignores these four fields entirely and reads
// ProviderConfig instead — see internal/vpnprovider/genericsocks5 for
// an example provider_config shape.
//
// EnforcePIDs is Session B Phase 7's addition: spec's eBPF Feature 1
// says the proxy_required_pids map gets populated "from profiles.yaml"
// but doesn't specify a field for it — this is that field. A PID
// listed here has its outbound connections transparently redirected
// through this profile's routing/credentials, per the eBPF
// cgroup/connect4 hook in ebpf/redirect. It applies regardless of which
// provider the profile uses.
type Profile struct {
	// Provider selects a registered internal/vpnprovider.Provider by
	// name (e.g. "iproyal", "socks5") — see main.go for which provider
	// packages are compiled in. Empty defaults to "iproyal".
	Provider string `yaml:"provider,omitempty"`
	// ProviderConfig is passed opaquely to Provider's factory
	// (vpnprovider.DecodeConfig turns it into that provider's own typed
	// config struct). Required for any non-"iproyal" provider; optional
	// for "iproyal" (see the legacy-field fallback above).
	ProviderConfig map[string]any `yaml:"provider_config,omitempty"`

	SubuserHash string `yaml:"subuser_hash,omitempty"`
	Username    string `yaml:"username,omitempty"`
	Password    string `yaml:"password,omitempty"`
	// UpstreamAddr overrides the global MITHRIL_UPSTREAM_ADDR for this
	// profile specifically — only meaningful for providers (like
	// "iproyal" and "socks5") that dial one fixed upstream address.
	UpstreamAddr string `yaml:"upstream_addr,omitempty"`

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
		provider := p.Provider
		if provider == "" {
			provider = legacyProvider
		}
		// Username/password are only required here for the legacy
		// "iproyal" shape (top-level fields, no provider_config). Any
		// other provider — or "iproyal" with an explicit
		// provider_config — validates its own required fields when
		// main.go constructs it (vpnprovider.New), since this package
		// has no business knowing what a given provider needs.
		if provider == legacyProvider && p.ProviderConfig == nil {
			if p.Username == "" {
				return fmt.Errorf("profiles: %s: username is required", name)
			}
			if p.Password == "" {
				return fmt.Errorf("profiles: %s: password is required", name)
			}
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
