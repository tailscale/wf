// wfpcli is a CLI tool for interacting with the Windows Filtering
// Platform (WFP), aka the Windows firewall.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/sys/windows"
	"inet.af/wf"
)

var (
	listProvidersC = &ffcli.Command{
		Name:       "list-providers",
		ShortUsage: "wfpcli list-providers",
		ShortHelp:  "List WFP providers.",
		Exec:       listProviders,
	}

	listLayersC = &ffcli.Command{
		Name:       "list-layers",
		ShortUsage: "wfpcli list-layers",
		ShortHelp:  "List WFP layers.",
		Exec:       listLayers,
	}

	listSublayersC = &ffcli.Command{
		Name:       "list-sublayers",
		ShortUsage: "wfpcli list-sublayers",
		ShortHelp:  "List WFP sublayers.",
		Exec:       listSublayers,
	}

	addSublayerFS       = flag.NewFlagSet("wfpcli add-sublayer", flag.ExitOnError)
	sublayerName        = addSublayerFS.String("name", "", "Sublayer name")
	sublayerDescription = addSublayerFS.String("description", "", "Sublayer description")
	sublayerPersistent  = addSublayerFS.Bool("persistent", false, "Whether the sublayer is persistent")
	sublayerWeight      = addSublayerFS.Int("weight", 1, "Sublayer weight")
	addSublayerC        = &ffcli.Command{
		Name:       "add-sublayer",
		ShortUsage: "wfpcli add-sublayer",
		ShortHelp:  "Add WFP sublayer.",
		FlagSet:    addSublayerFS,
		Exec:       addSublayer,
	}

	delSublayerC = &ffcli.Command{
		Name:       "del-sublayer",
		ShortUsage: "wfpcli del-sublayer <guid>",
		ShortHelp:  "Delete WFP sublayer.",
		Exec:       delSublayer,
	}

	rootFS  = flag.NewFlagSet("wfpcli", flag.ExitOnError)
	dynamic = rootFS.Bool("dynamic", false, "Use a dynamic WFP session")
	root    = &ffcli.Command{
		ShortUsage:  "wfpcli <subcommand>",
		FlagSet:     rootFS,
		Subcommands: []*ffcli.Command{listProvidersC, listLayersC, listSublayersC, addSublayerC, delSublayerC},
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
	}
)

func main() {
	if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}

func session() (*wf.Session, error) {
	return wf.New(&wf.SessionOptions{
		Name:        "wfpcli",
		Description: "WFP CLI",
		Dynamic:     *dynamic,
	})
}

func mustGUID() windows.GUID {
	ret, err := windows.GenerateGUID()
	if err != nil {
		panic(err)
	}
	return ret
}

func displayName(guid windows.GUID, name string) string {
	if name != "" {
		return name
	}
	return wf.GUIDName(guid)
}

func listProviders(_ context.Context, _ []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	providers, err := sess.Providers()
	if err != nil {
		return fmt.Errorf("listing providers: %w", err)
	}

	for _, provider := range providers {
		fmt.Printf("%s\n", displayName(provider.Key, provider.Name))
		fmt.Printf("  GUID: %s\n", provider.Key)
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

func listLayers(_ context.Context, _ []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	layers, err := sess.Layers()
	if err != nil {
		return fmt.Errorf("listing layers: %w", err)
	}

	for _, layer := range layers {
		fmt.Printf("%s\n", displayName(layer.Key, layer.Name))
		fmt.Printf("  GUID: %s\n", layer.Key)
		fmt.Printf("  Name: %q\n", layer.Name)
		if layer.Description != "" {
			fmt.Printf("  Description: %q\n", layer.Description)
		}
		for _, field := range layer.Fields {
			fmt.Printf("  Field: %s\n", wf.GUIDName(field.Key))
			fmt.Printf("    GUID: %s\n", field.Key)
			fmt.Printf("    Type: %s\n", field.Type)
		}
		fmt.Printf("\n")
	}

	return nil
}

func listSublayers(_ context.Context, _ []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	sublayers, err := sess.Sublayers(nil)
	if err != nil {
		return fmt.Errorf("listing WFP sublayers: %w", err)
	}

	for _, sublayer := range sublayers {
		fmt.Printf("%s\n", displayName(sublayer.Key, sublayer.Name))
		fmt.Printf("  GUID: %s\n", sublayer.Key)
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

func addSublayer(_ context.Context, _ []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	sl := &wf.Sublayer{
		Key:         mustGUID(),
		Name:        *sublayerName,
		Description: *sublayerDescription,
		Persistent:  *sublayerPersistent,
		Weight:      uint16(*sublayerWeight),
	}

	if err := sess.AddSublayer(sl); err != nil {
		return fmt.Errorf("creating sublayer: %w", err)
	}

	fmt.Printf("Created sublayer %s\n", sl.Key)
	return nil
}

func delSublayer(_ context.Context, args []string) error {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "GUID is required\n")
		return flag.ErrHelp
	}

	guid, err := windows.GUIDFromString(args[0])
	if err != nil {
		return fmt.Errorf("Parsing GUID: %w", err)
	}

	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	if err := sess.DeleteSublayer(guid); err != nil {
		return fmt.Errorf("deleting sublayer: %w", err)
	}

	fmt.Printf("Deleted sublayer %s\n", guid)

	return nil
}
