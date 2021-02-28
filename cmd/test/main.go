package main

import (
	"fmt"

	"inet.af/winfirewall"
)

func main() {
	sess, err := winfirewall.New()
	if err != nil {
		fmt.Println("fail:", err)
	}
	defer sess.Close()

	filters, err := sess.Filters()
	if err != nil {
		panic(err)
	}

	for _, filter := range filters {
		fmt.Printf("[%s]\n  > %s\n  > %s\n  > %s\n\n", filter.Name, filter.Description, winfirewall.GuidNames[filter.LayerKey], winfirewall.GuidNames[filter.SubLayerKey])
	}

	fmt.Println("got", len(filters), "filters")

	// guid, err := windows.GenerateGUID()
	// if err != nil {
	// 	panic(err)
	// }

	// if err := sess.AddProvider(&winfirewall.Provider{
	// 	Key:         guid,
	// 	Name:        "TEST PROVIDER",
	// 	Description: "YES INDEED",
	// }); err != nil {
	// 	panic(err)
	// }

	// providers, err := sess.Providers()
	// if err != nil {
	// 	panic(err)
	// }
	// for _, provider := range providers {
	// 	fmt.Printf("%#v\n", provider)
	// }

	// layers, err := sess.Sublayers(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("before layers", len(layers))

	// guid, err := windows.GenerateGUID()
	// if err != nil {
	// 	panic(err)
	// }

	// sl := &winfirewall.Sublayer{
	// 	Key:         guid,
	// 	Name:        "MY COOL LAYER",
	// 	Description: "HOLY SHIT IT WORKS",
	// 	Weight:      0x100,
	// }

	// if err := sess.AddSublayer(sl); err != nil {
	// 	panic(err)
	// }

	// layers, err = sess.Sublayers(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("after layers", len(layers))
	// for _, layer := range layers {
	// 	fmt.Printf("%#v\n", layer)
	// }

	// if err := sess.DeleteSublayer(guid); err != nil {
	// 	panic(err)
	// }
	// layers, err = sess.Sublayers(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("after layers2", len(layers))
}
