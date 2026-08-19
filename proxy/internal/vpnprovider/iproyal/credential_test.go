package iproyal

import "testing"

// These cases are the literal examples from IPRoyal's documentation
// (docs.iproyal.com/proxies/residential/proxy/location and .../rotation),
// not invented — buildPassword must reproduce them exactly.
func TestBuildPassword_MatchesIPRoyalDocs(t *testing.T) {
	cases := []struct {
		name string
		base string
		opts credentialOptions
		want string
	}{
		{
			name: "multi-country",
			base: "password321",
			opts: credentialOptions{Country: "dk,it,ie"},
			want: "password321_country-dk,it,ie",
		},
		{
			name: "country+city",
			base: "password321",
			opts: credentialOptions{Country: "de", City: "berlin"},
			want: "password321_country-de_city-berlin",
		},
		{
			name: "us state",
			base: "password321",
			opts: credentialOptions{Country: "us", State: "iowa"},
			want: "password321_country-us_state-iowa",
		},
		{
			name: "isp",
			base: "password321",
			opts: credentialOptions{Country: "gb", City: "birmingham", ISP: "skyuklimited"},
			want: "password321_country-gb_city-birmingham_isp-skyuklimited",
		},
		{
			name: "region",
			base: "password321",
			opts: credentialOptions{Region: "europe"},
			want: "password321_region-europe",
		},
		{
			name: "geolocation",
			base: "password321",
			opts: credentialOptions{Geolocation: "54.6872,25.2797,10"},
			want: "password321_geolocation-54.6872,25.2797,10",
		},
		{
			name: "geolocation strict",
			base: "password321",
			opts: credentialOptions{Geolocation: "54.6872,25.2797,10,strict"},
			want: "password321_geolocation-54.6872,25.2797,10,strict",
		},
		{
			name: "sticky session with lifetime",
			base: "password321",
			opts: credentialOptions{Country: "br", SessionID: "sgn34f3e", Lifetime: "10m"},
			want: "password321_country-br_session-sgn34f3e_lifetime-10m",
		},
		{
			name: "no options — base password unchanged",
			base: "password321",
			opts: credentialOptions{},
			want: "password321",
		},
		{
			name: "forcerandom",
			base: "password321",
			opts: credentialOptions{ForceRandom: true},
			want: "password321_forcerandom-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPassword(tc.base, tc.opts)
			if got != tc.want {
				t.Errorf("buildPassword(%q, %+v) = %q, want %q", tc.base, tc.opts, got, tc.want)
			}
		})
	}
}
