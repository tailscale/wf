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
	sess.Test()
}
