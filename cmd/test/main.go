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
	fmt.Println("open!")
	layers, err := sess.Layers()
	if err != nil {
		panic(err)
	}
	for _, layer := range layers {
		fmt.Printf("%#v\n", layer)
	}
}
