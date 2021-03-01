// dumpproviders is a tool that lists all WFP providers on the current
// system.
package main

import (
	"fmt"
	"os"

	"inet.af/wf"
)

func main() {
	if err := DumpProviders(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func DumpProviders() error {
	session, err := wf.New(&wf.SessionOptions{
		Name:        "DumpProviders",
		Description: "Provider dumping tool",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer session.Close()

	providers, err := session.Providers()
	if err != nil {
		return fmt.Errorf("listing WFP providers: %w", err)
	}

	for _, provider := range providers {
		fmt.Printf("%s\n", wf.GUIDName(provider.Key))
		fmt.Printf("  Name: %q\n", provider.Name)
		if provider.Description != "" {
			fmt.Printf("  Description: %q\n", provider.Description)
		}
		fmt.Printf("  Persistent: %v\n", provider.Persistent)
		if len(provider.Data) > 0 {
			fmt.Printf("  Data: %v\n", provider.Data)
		}
		if provider.ServiceName != "" {
			fmt.Printf("  Service name: %s\n", provider.ServiceName)
		}
		fmt.Printf("  Disabled: %v\n", provider.Disabled)
		fmt.Printf("\n")
	}

	return nil
}
