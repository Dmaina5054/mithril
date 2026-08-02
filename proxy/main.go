// Command mithril-proxy is the SOCKS5 consumer proxy for IPRoyal
// residential proxies, built out phase-by-phase per docs/mithril-infra-spec.docx
// Session B.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mithril-proxy: scaffold only — no phases wired up yet")
	os.Exit(1)
}
