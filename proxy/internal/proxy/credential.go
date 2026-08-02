package proxy

import (
	"fmt"
	"strings"
)

// CredentialOptions encodes IPRoyal's password-suffix targeting keys —
// confirmed against docs.iproyal.com/proxies/residential/proxy/location
// and .../rotation. Location/session parameters go in the PASSWORD
// field, not the username: "password321_country-br_session-sgn34f3e_lifetime-10m".
type CredentialOptions struct {
	Country     string // e.g. "us", or "dk,it,ie" for a random pick among several
	City        string // requires Country
	State       string // US only
	ISP         string // requires City
	Region      string // e.g. "europe" — alternative to Country
	Geolocation string // "lat,lon,radius" or "lat,lon,radius,strict"
	SessionID   string // 8-char alnum; empty means rotating (no sticky keys added)
	Lifetime    string // required alongside SessionID, e.g. "2h", "10m"
	ForceRandom bool   // expands location pool, reduces rotation frequency
}

// BuildPassword appends opts' IPRoyal targeting keys to basePassword in
// their documented order: country, city, state, isp, region,
// geolocation, session+lifetime, forcerandom. Empty fields are omitted
// entirely rather than emitted as "_key-".
func BuildPassword(basePassword string, opts CredentialOptions) string {
	var b strings.Builder
	b.WriteString(basePassword)

	if opts.Country != "" {
		fmt.Fprintf(&b, "_country-%s", opts.Country)
	}
	if opts.City != "" {
		fmt.Fprintf(&b, "_city-%s", opts.City)
	}
	if opts.State != "" {
		fmt.Fprintf(&b, "_state-%s", opts.State)
	}
	if opts.ISP != "" {
		fmt.Fprintf(&b, "_isp-%s", opts.ISP)
	}
	if opts.Region != "" {
		fmt.Fprintf(&b, "_region-%s", opts.Region)
	}
	if opts.Geolocation != "" {
		fmt.Fprintf(&b, "_geolocation-%s", opts.Geolocation)
	}
	if opts.SessionID != "" {
		fmt.Fprintf(&b, "_session-%s", opts.SessionID)
		if opts.Lifetime != "" {
			fmt.Fprintf(&b, "_lifetime-%s", opts.Lifetime)
		}
	}
	if opts.ForceRandom {
		b.WriteString("_forcerandom-1")
	}

	return b.String()
}
