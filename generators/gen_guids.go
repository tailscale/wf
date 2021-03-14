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
	var generated []guidName

	for {
		l, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fatalf("reading from .h: %v", err)
		}
		l = strings.TrimSpace(l)

		if !strings.HasPrefix(l, "DEFINE_GUID(") {
			continue
		}

		name, g1, g2, g3, g4, err := readGUIDDef(r, l)
		if err != nil {
			fatalf("reading GUID def: %v", err)
		}

		defs[name.Type()] = append(defs[name.Type()], fmt.Sprintf("%s = %s{%s, %s, %s, [8]byte{%s}}", name.VarName(), name.GoType(), g1, g2, g3, g4))
		generated = append(generated, name)
	}

	var types []string
	for typ := range defs {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		fmt.Fprintf(&out, "// Well-known %s IDs.\n", strings.ToLower(typ))
		fmt.Fprintf(&out, "var (\n")
		vars := defs[typ]
		sort.Strings(vars)
		for _, v := range vars {
			fmt.Fprintf(&out, "%s\n", v)
		}
		fmt.Fprintf(&out, ")\n\n")
	}

	sort.Slice(generated, func(i, j int) bool { return generated[i] < generated[j] })

	out.WriteString("var guidNames = map[windows.GUID]string{\n")
	for _, name := range generated {
		v := name.VarName()
		if name.GoType() != "windows.GUID" {
			v = fmt.Sprintf("windows.GUID(%s)", v)
		}
		fmt.Fprintf(&out, "%s: %q,\n", v, name.String())
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

type guidName string

// Type returns the datatype of the GUID.
// e.g. FWPM_LAYER_BLAH_BLAH -> "layer"
func (g guidName) Type() string {
	ret := strings.ToLower(strings.Split(string(g), "_")[1])
	switch ret {
	case "condition":
		return "field"
	default:
		return ret
	}
}

func (g guidName) Exported() bool {
	switch g.Type() {
	case "layer", "field":
		return true
	default:
		return false
	}
}

// GoType returns the Go type to use when declaring the GUID.
// e.g. FWPM_LAYER_BLAH -> LayerID
func (g guidName) GoType() string {
	if g.Exported() {
		return strings.Title(g.Type()) + "ID"
	}
	return "windows.GUID"
}

// String returns the pretty string for the GUID.
// e.g. "FWPM_LAYER_BLAH" -> "BLAH"
// e.g. "FWPM_SUBLAYER_LIPS" -> "SUBLAYER_LIPS"
func (g guidName) String() string {
	if g.Exported() {
		return strings.SplitN(string(g), "_", 3)[2]
	}
	return strings.SplitN(string(g), "_", 2)[1]
}

var keepUpper = map[string]bool{
	"ALE":  true,
	"DCOM": true,
	"EP":   true,
	"ICMP": true,
	"ID":   true,
	"IKE":  true,
	"IP":   true,
	"KM":   true,
	"LIPS": true,
	"MAC":  true,
	"NAP":  true,
	"OUI":  true,
	"QM":   true,
	"RPC":  true,
	"SNAP": true,
	"TCP":  true,
	"UDP":  true,
	"UM":   true,
	"UUID": true,
	"VLAN": true,
	"WFP":  true,
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

func (g guidName) VarName() string {
	fs := strings.Split(string(g), "_")
	if g.Exported() {
		fs[0] = ""
	} else {
		fs[0] = "guid"
	}
	fs[1] = g.Type()

	for i, f := range fs[1:] {
		if keepUpper[f] {
			continue
		}
		if rep, ok := replacements[f]; ok {
			fs[i+1] = rep
		} else {
			fs[i+1] = strings.Title(strings.ToLower(f))
		}
	}

	return strings.Join(fs, "")
}

func readGUIDDef(r *bufio.Reader, l string) (name guidName, g1, g2, g3, g4 string, err error) {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		return strings.TrimSuffix(s, ",")
	}

	var n string
	if strings.HasPrefix(l, "DEFINE_GUID(FWPM_") {
		n = strings.Split(l, "(")[1]
	} else {
		n, err = r.ReadString('\n')
		if err != nil {
			return
		}
	}
	name = guidName(clean(n))

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
