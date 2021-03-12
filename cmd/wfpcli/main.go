// wfpcli is a CLI tool for interacting with the Windows Filtering
// Platform (WFP), aka the Windows firewall.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

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

	addProviderFS       = flag.NewFlagSet("wfpcli add-provider", flag.ExitOnError)
	providerName        = addProviderFS.String("name", "", "Provider name")
	providerDescription = addProviderFS.String("description", "", "Provider description")
	providerPersistent  = addProviderFS.Bool("persistent", false, "Whether the provider is persistent")
	providerServiceName = addProviderFS.String("service", "", "Service name")
	addProviderC        = &ffcli.Command{
		Name:       "add-provider",
		ShortUsage: "wfpcli add-provider",
		ShortHelp:  "Add WFP provider",
		FlagSet:    addProviderFS,
		Exec:       addProvider,
	}

	delProviderC = &ffcli.Command{
		Name:       "del-provider",
		ShortUsage: "wfpcli del-provider <guid>",
		ShortHelp:  "Delete WFP provider.",
		Exec:       delProvider,
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
	sublayerProvider    = addSublayerFS.String("provider", "", "Owner of the sublayer")
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

	listRulesC = &ffcli.Command{
		Name:       "list-rules",
		ShortUsage: "wfpcli list-rules",
		ShortHelp:  "List WFP rules.",
		Exec:       listRules,
	}

	testC = &ffcli.Command{
		Name:       "test",
		ShortUsage: "wfpcli list-rules",
		ShortHelp:  "List WFP rules.",
		Exec:       test,
	}

	rootFS  = flag.NewFlagSet("wfpcli", flag.ExitOnError)
	dynamic = rootFS.Bool("dynamic", false, "Use a dynamic WFP session")
	root    = &ffcli.Command{
		ShortUsage:  "wfpcli <subcommand>",
		FlagSet:     rootFS,
		Subcommands: []*ffcli.Command{listProvidersC, addProviderC, delProviderC, listLayersC, listSublayersC, addSublayerC, delSublayerC, listRulesC, testC},
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

func addProvider(context.Context, []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	p := &wf.Provider{
		Key:         mustGUID(),
		Name:        *providerName,
		Description: *providerDescription,
		Persistent:  *providerPersistent,
		ServiceName: *providerServiceName,
	}

	if err := sess.AddProvider(p); err != nil {
		return fmt.Errorf("adding provider: %w", err)
	}

	fmt.Printf("Created provider %s\n", p.Key)

	return nil
}

func delProvider(_ context.Context, args []string) error {
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

	if err := sess.DeleteProvider(guid); err != nil {
		return fmt.Errorf("deleting provider: %w", err)
	}

	fmt.Printf("Deleted provider %s\n", guid)

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
	if *sublayerProvider != "" {
		guid, err := windows.GUIDFromString(*sublayerProvider)
		if err != nil {
			return fmt.Errorf("Parsing provider GUID: %w", err)
		}
		sl.Provider = &guid
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

func listRules(context.Context, []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	rules, err := sess.Rules()
	if err != nil {
		return fmt.Errorf("getting rules: %w", err)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Key.String() < rules[j].Key.String()
	})

	for _, rule := range rules {
		fmt.Printf("%s\n", displayName(rule.Key, rule.Name))
		fmt.Printf("  GUID: %s\n", rule.Key)
		fmt.Printf("  Name: %q\n", rule.Name)
		if rule.Description != "" {
			fmt.Printf("  Description: %q\n", rule.Description)
		}
		fmt.Printf("  Layer: %s\n", wf.GUIDName(rule.Layer))
		fmt.Printf("  Sublayer: %s\n", wf.GUIDName(rule.Sublayer))
		fmt.Printf("  Weight: 0x%02x\n", rule.Weight)
		fmt.Printf("  Action: %s\n", rule.Action)
		if rule.Callout != (windows.GUID{}) {
			fmt.Printf("  Callout: %s\n", wf.GUIDName(rule.Callout))
		}
		if rule.Action == wf.ActionCalloutTerminating || rule.Action == wf.ActionCalloutUnknown {
			fmt.Printf("  Permit if missing: %v\n", rule.PermitIfMissing)
		}
		fmt.Printf("  Persistent: %v\n", rule.Persistent)
		fmt.Printf("  Boot-time: %v\n", rule.BootTime)
		if rule.Provider != nil {
			//fmt.Printf("  Provider: %s\n", wf.GUIDName(*rule.Provider))
		}
		if rule.Disabled {
			fmt.Printf("  Disabled: %v\n", rule.Disabled)
		}
		for _, cond := range rule.Conditions {
			fmt.Printf("  Condition: %s\n", cond)
		}
		fmt.Printf("\n")
	}
	fmt.Printf("Dumped %d rules\n", len(rules))
	return nil
}

var guidLayerALEAuthRecvAcceptV4 = windows.GUID{
	Data1: 0xe1cd9fe7,
	Data2: 0xf4b5,
	Data3: 0x4273,
	Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
}

var guidSublayerUniversal = windows.GUID{
	Data1: 0xeebecc03,
	Data2: 0xced4,
	Data3: 0x4380,
	Data4: [8]byte{0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74},
}

var guidConditionIPLocalPort = windows.GUID{
	Data1: 0x0c1ba1af,
	Data2: 0x5765,
	Data3: 0x453f,
	Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
}

var guidConditionIPLocalInterface = windows.GUID{
	Data1: 0x4cd62a49,
	Data2: 0x59c3,
	Data3: 0x4969,
	Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
}

func test(context.Context, []string) error {
	sess, err := session()
	if err != nil {
		return fmt.Errorf("creating WFP session: %w", err)
	}
	defer sess.Close()

	sess.Dump()

	// guid, err := windows.GenerateGUID()
	// if err != nil {
	// 	panic(err)
	// }

	// r := &wf.Rule{
	// 	Key:      guid,
	// 	Name:     "test2",
	// 	Layer:    guidLayerALEAuthRecvAcceptV4,
	// 	Sublayer: guidSublayerUniversal,
	// 	Weight:   10,
	// 	Conditions: []*wf.Match{
	// 		&wf.Match{
	// 			Key:   guidConditionIPLocalInterface,
	// 			Op:    wf.MatchTypeEqual,
	// 			Value: uint64(5),
	// 		},
	// 	},
	// 	Action: wf.ActionPermit,
	// }

	// if err := sess.AddRule(r); err != nil {
	// 	return fmt.Errorf("failed to add rule: %w", err)
	// }

	return nil
}
