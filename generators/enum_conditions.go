// enum_conditions enumerates all the match conditions that WFP offers
// in its various layers, along with the Go data type that WFP is
// expecting to work with.
//
// This tool is used to figure out the set of matcher structs that
// need to be built, based on the actual filtering options offered by
// WFP. It must be run on a Windows system, and thus isn't part of the
// basic `go generate` run. To update the conditions list, build and
// run this tool by hand.
package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"

	"golang.org/x/sys/windows"
	"inet.af/wf"
)

func fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	session, err := wf.New(nil)
	if err != nil {
		fatalf("creating WFP session: %v", err)
	}
	defer session.Close()

	layers, err := session.Layers()
	if err != nil {
		fatalf("listing WFP layers: %v", err)
	}

	fields := map[windows.GUID]map[reflect.Type]bool{}
	for _, l := range layers {
		for _, f := range l.Fields {
			if _, ok := fields[f.Key]; !ok {
				fields[f.Key] = map[reflect.Type]bool{}
			}
			fields[f.Key][f.Type] = true
		}
	}

	var out []*wf.Field
	for guid, m := range fields {
		for t := range m {
			out = append(out, &wf.Field{Key: guid, Type: t})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return wf.GUIDName(out[i].Key) < wf.GUIDName(out[j].Key)
	})

	for _, field := range out {
		fmt.Printf("%s %s %s\n", wf.GUIDName(field.Key), field.Key, field.Type)
	}
}
