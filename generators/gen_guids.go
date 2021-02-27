package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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
	out.WriteString(`package winfirewall

import "golang.org/x/sys/windows"

`)

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

		fmt.Fprintf(&out, `var %s = windows.GUID{
Data1: %s,
Data2: %s,
Data3: %s,
Data4: [8]byte{%s},
}

`, varName(name), g1, g2, g3, g4)
		generated = append(generated, name)
	}

	out.WriteString("var guidNames = map[windows.GUID]string{\n")
	for _, name := range generated {
		fmt.Fprintf(&out, "%s: %q,\n", varName(name), name)
	}
	out.WriteString("}\n")

	// bs, err := format.Source(out.Bytes())
	// if err != nil {
	// 	fatalf("formatting source code: %v", err)
	// }

	if err := ioutil.WriteFile(outPath, out.Bytes(), 0644); err != nil {
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
	"OUI",
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
	"IPSEC":     "IPSec",
	"IKEV2":     "IKEv2",
	"AUTHIP":    "AuthIP",
	"IPPACKET":  "IPPacket",
	"IPFORWARD": "IPForward",
	"IKEEXT":    "IKEExt",
	"EPMAP":     "EPMap",
}

func varName(guidName string) string {
	fs := strings.Split(guidName, "_")
	fs[0] = "guid"
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
