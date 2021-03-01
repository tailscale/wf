// dumpsublayers is a tool that lists all WFP sublayers on the current
// system.
package main

import (
	"fmt"
	"os"

	"inet.af/wf"
)

func main() {
	if err := DumpSublayers(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func DumpSublayers() error {
	session, err := wf.New(&wf.SessionOptions{
		Name:        "DumpSublayers",
		Description: "Sublayer dumping tool",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer session.Close()

	sublayers, err := session.Sublayers(nil)
	if err != nil {
		return fmt.Errorf("listing WFP sublayers: %w", err)
	}

	for _, sublayer := range sublayers {
		fmt.Printf("%s\n", wf.GUIDName(sublayer.Key))
		fmt.Printf("  Name: %q\n", sublayer.Name)
		if sublayer.Description != "" {
			fmt.Printf("  Description: %q\n", sublayer.Description)
		}
		fmt.Printf("  Persistent: %v\n", sublayer.Persistent)
		if sublayer.Provider != nil {
			fmt.Printf("  Provider: %s\n", *sublayer.Provider)
		}
		if len(sublayer.ProviderData) > 0 {
			fmt.Printf("  Provider data: %v\n", sublayer.ProviderData)
		}
		fmt.Printf("  Weight: %d\n", sublayer.Weight)
		fmt.Printf("\n")
	}

	return nil
}
