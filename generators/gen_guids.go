package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

func fatalf(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
	os.Exit(1)
}

var generated []string

func main() {
	fwpmuPath, outPath := os.Args[1], os.Args[2]

	f, err := os.Open(fwpmuPath)
	if err != nil {
		fatalf("reading .h: %v", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)

	var out bytes.Buffer
	out.WriteString(`package wf

import "golang.org/x/sys/windows"

`)

	defs := map[string][]string{}

	for {
		l, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fatalf("reading from .h: %v", err)
		}
		l = strings.TrimSpace(l)

		if !strings.HasPrefix(l, "DEFINE_GUID") {
			continue
		}

		name, g1, g2, g3, g4, err := readGUIDDef(r, l)
		if err != nil {
			fatalf("reading GUID def: %v", err)
		}

		defs[guidType(name)] = append(defs[guidType(name)], fmt.Sprintf("%s = %s{%s, %s, %s, [8]byte{%s}}", varName(name), typeName(name), g1, g2, g3, g4))
		generated = append(generated, name)
	}

	var types []string
	for typ := range defs {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		fmt.Fprintf(&out, "var (\n")
		vars := defs[typ]
		sort.Strings(vars)
		for _, v := range vars {
			fmt.Fprintf(&out, "%s\n", v)
		}
		fmt.Fprintf(&out, ")\n\n")
	}

	sort.Strings(generated)

	out.WriteString("var guidNames = map[windows.GUID]string{\n")
	for _, name := range generated {
		v := varName(name)
		if typeName(name) != "windows.GUID" {
			v = fmt.Sprintf("windows.GUID(%s)", v)
		}
		fmt.Fprintf(&out, "%s: %q,\n", v, stringName(name))
	}
	out.WriteString("}\n")

	bs, err := format.Source(out.Bytes())
	if err != nil {
		fatalf("formatting source code: %v", err)
	}

	if err := ioutil.WriteFile(outPath, bs, 0644); err != nil {
		fatalf("writing generated file: %v", err)
	}
}

var keepUpper = []string{
	"ALE",
	"DCOM",
	"EP",
	"ICMP",
	"ID",
	"IKE",
	"IP",
	"KM",
	"LIPS",
	"MAC",
	"NAP",
	"OUI",
	"QM",
	"RPC",
	"SNAP",
	"TCP",
	"UDP",
	"UM",
	"UUID",
	"VLAN",
	"WFP",
}
var replacements = map[string]string{
	"AUTHIP":    "AuthIP",
	"EPMAP":     "EPMap",
	"IKEEXT":    "IKEExt",
	"IKEV2":     "IKEv2",
	"IPFORWARD": "IPForward",
	"IPPACKET":  "IPPacket",
	"IPSEC":     "IPSec",
	"VSWITCH":   "VSwitch",
}

var exported = map[string]bool{
	"LAYER": true,
}

func stringName(name string) string {
	if exported[guidType(name)] {
		return strings.SplitN(name, "_", 3)[2]
	}
	return strings.SplitN(name, "_", 2)[1]
}

func varName(guidName string) string {
	fs := strings.Split(guidName, "_")
	if exported[fs[1]] {
		fs[0] = ""
	} else {
		fs[0] = "guid"
	}
remapLoop:
	for i, f := range fs[1:] {
		for _, k := range keepUpper {
			if k == f {
				continue remapLoop
			}
		}
		if rep, ok := replacements[f]; ok {
			fs[i+1] = rep
		} else {
			fs[i+1] = strings.Title(strings.ToLower(f))
		}
	}

	return strings.Join(fs, "")
}

func typeName(name string) string {
	switch guidType(name) {
	case "LAYER":
		return "LayerID"
	default:
		return "windows.GUID"
	}
}

func guidType(name string) string {
	fs := strings.Split(name, "_")
	return fs[1]
}

func readGUIDDef(r *bufio.Reader, l string) (name, g1, g2, g3, g4 string, err error) {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		return strings.TrimSuffix(s, ",")
	}

	if strings.HasPrefix(l, "DEFINE_GUID(FWPM_") {
		name = strings.Split(l, "(")[1]
	} else {
		name, err = r.ReadString('\n')
		if err != nil {
			return
		}
	}
	name = clean(name)

	g1, err = r.ReadString('\n')
	if err != nil {
		return
	}
	g1 = clean(g1)

	g2, err = r.ReadString('\n')
	if err != nil {
		return
	}
	g2 = clean(g2)

	g3, err = r.ReadString('\n')
	if err != nil {
		return
	}
	g3 = clean(g3)

	g4, err = r.ReadString('\n')
	if err != nil {
		return
	}
	g4 = clean(g4)

	return
}
