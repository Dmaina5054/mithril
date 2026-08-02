// Command apismoke is the Session B Phase 1 gate check: connect to the
// IPRoyal API and print the entry nodes (and account info) it returns.
// Not a long-running tool — run it manually, read the output, fix the
// client if anything looks wrong.
//
// Usage:
//
//	IPROYAL_API_TOKEN=<real token> go run ./cmd/apismoke
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dmaina5054/mithril/proxy/internal/iproyal"
)

func main() {
	token := os.Getenv("IPROYAL_API_TOKEN")
	if token == "" || token == "smoke-test-placeholder" {
		fmt.Fprintln(os.Stderr, "apismoke: set IPROYAL_API_TOKEN to a real token (the .env placeholder won't authenticate)")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := iproyal.NewClient(token)

	fmt.Println("=== GET /me ===")
	me, err := client.Me(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apismoke: /me failed: %v\n", err)
		os.Exit(1)
	}
	printJSON(me)

	fmt.Println("\n=== GET /access/entry-nodes ===")
	nodes, err := client.EntryNodes(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apismoke: /access/entry-nodes failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d entry node(s):\n", len(nodes))
	for i, n := range nodes {
		fmt.Printf("  [%d] ", i)
		printJSON(n)
	}

	fmt.Println("\n=== GET /residential-subusers ===")
	subusers, err := client.ListSubusers(ctx, iproyal.SubuserListOptions{PerPage: 20})
	if err != nil {
		fmt.Fprintf(os.Stderr, "apismoke: /residential-subusers failed: %v\n", err)
		os.Exit(1)
	}
	printJSON(subusers)

	fmt.Println("\napismoke: all endpoints reachable")
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("(unprintable: %v)\n", err)
		return
	}
	fmt.Println(string(b))
}
