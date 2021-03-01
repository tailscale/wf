// dumplayers is a tool that lists all WFP layers on the current
// system, along with the field names and types that the layer makes
// available to filter rules within that layer.
package main

import (
	"fmt"
	"os"

	"inet.af/wf"
)

func main() {
	if err := DumpLayers(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func DumpLayers() error {
	session, err := wf.New(&wf.SessionOptions{
		Name:        "DumpLayers",
		Description: "Layer dumping tool",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer session.Close()

	layers, err := session.Layers()
	if err != nil {
		return fmt.Errorf("listing WFP layers: %w", err)
	}

	for _, layer := range layers {
		fmt.Printf("%s (name %q, description %q)\n", wf.GUIDName(layer.Key), layer.Name, layer.Description)
		for _, field := range layer.Fields {
			fmt.Printf("  > %s (%s)\n", wf.GUIDName(field.Key), field.Type)
		}
		fmt.Printf("\n")
	}

	return nil
}
