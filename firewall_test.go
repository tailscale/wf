package wf

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

func skipIfUnprivileged(t *testing.T) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		panic(fmt.Sprintf("getting process token: %v", err))
	}
	defer tok.Close()
	if !tok.IsElevated() {
		t.Skipf("skipping test that requires admin privileges")
	}
}

func TestSession(t *testing.T) {
	skipIfUnprivileged(t)

	tests := []struct {
		name string
		opts *Options
	}{
		{
			name: "nil",
			opts: nil,
		},
		{
			name: "name_only",
			opts: &Options{
				Name: "test",
			},
		},
		{
			name: "name_and_desc",
			opts: &Options{
				Name:        "test2",
				Description: "unit test session",
			},
		},
		{
			name: "dynamic",
			opts: &Options{
				Name:    "test2",
				Dynamic: true,
			},
		},
		{
			name: "tx_timeout",
			opts: &Options{
				Name:                    "test2",
				TransactionStartTimeout: 5 * time.Minute,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sess, err := New(test.opts)
			if err != nil {
				t.Fatalf("failed to open session: %v", err)
			}
			if err := sess.Close(); err != nil {
				t.Errorf("closing session: %v", err)
			}
		})
	}
}

var (
	stringT = reflect.TypeOf("")
	taiT    = reflect.TypeOf(TokenAccessInformation{})
	ipT     = reflect.TypeOf(netaddr.IP{})
	u8T     = reflect.TypeOf(uint8(0))
	u16T    = reflect.TypeOf(uint16(0))
	u32T    = reflect.TypeOf(uint32(0))
	u64T    = reflect.TypeOf(uint64(0))
	sidT    = reflect.TypeOf(&windows.SID{})
	bytesT  = reflect.TypeOf([]byte(nil))
	indexT  = reflect.TypeOf(BitmapIndex(0))
)

func TestLayers(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	layers, err := s.Layers()
	if err != nil {
		t.Fatalf("getting layers: %v", err)
	}

	// Try to find a couple of the well-known layers that Windows
	// should definitely have.
	wantLayers := map[LayerID]*Layer{
		LayerALEAuthRecvAcceptV4: {
			ID:              LayerALEAuthRecvAcceptV4,
			KernelID:        44,
			Name:            "ALE Receive/Accept v4 Layer",
			DefaultSublayer: guidSublayerUniversal,
			Fields: []*Field{
				{FieldALEAppID, stringT},
				{FieldALENAPContext, u32T},
				{FieldALEPackageID, sidT},
				{FieldALERemoteMachineID, taiT},
				{FieldALERemoteUserID, taiT},
				{FieldALESecurityAttributeFqbnValue, bytesT},
				{FieldALESioFirewallSystemPort, u32T},
				{FieldALEUserID, taiT},
				{FieldArrivalInterfaceIndex, u32T},
				{FieldArrivalInterfaceType, u32T},
				{FieldArrivalTunnelType, u32T},
				{FieldBitmapIPLocalAddress, indexT},
				{FieldBitmapIPLocalPort, indexT},
				{FieldBitmapIPRemoteAddress, indexT},
				{FieldBitmapIPRemotePort, indexT},
				{FieldCompartmentID, u32T},
				{FieldCurrentProfileID, u32T},
				{FieldFlags, u32T},
				{FieldInterfaceIndex, u32T},
				{FieldInterfaceQuarantineEpoch, u64T},
				{FieldInterfaceType, u32T},
				{FieldIPArrivalInterface, u64T},
				{FieldIPLocalAddress, ipT},
				{FieldIPLocalAddressType, u8T},
				{FieldIPLocalInterface, u64T},
				{FieldIPLocalPort, u16T},
				{FieldIPNexthopInterface, u64T},
				{FieldIPProtocol, u8T},
				{FieldIPRemoteAddress, ipT},
				{FieldIPRemotePort, u16T},
				{FieldNexthopInterfaceIndex, u32T},
				{FieldNexthopInterfaceType, u32T},
				{FieldNexthopSubInterfaceIndex, u32T},
				{FieldNexthopTunnelType, u32T},
				{FieldOriginalICMPType, u16T},
				{FieldOriginalProfileID, u32T},
				{FieldReauthorizeReason, u32T},
				{FieldSubInterfaceIndex, u32T},
				{FieldTunnelType, u32T},
			},
		},
		LayerStreamV4Discard: {
			ID:              LayerStreamV4Discard,
			KernelID:        21,
			Name:            "Stream v4 Discard Layer",
			DefaultSublayer: guidSublayerUniversal,
			Fields: []*Field{
				{FieldCompartmentID, u32T},
				{FieldDirection, u32T},
				{FieldFlags, u32T},
				{FieldIPLocalAddress, ipT},
				{FieldIPLocalAddressType, u8T},
				{FieldIPLocalPort, u16T},
				{FieldIPRemoteAddress, ipT},
				{FieldIPRemotePort, u16T},
			},
		},
	}

	for guid, want := range wantLayers {
		found := false
		for _, got := range layers {
			if got.ID != guid {
				continue
			}
			found = true
			sort.Slice(got.Fields, func(i, j int) bool {
				return got.Fields[i].ID.String() < got.Fields[j].ID.String()
			})
			fieldCmp := func(a, b *Field) bool {
				return a.ID == b.ID && a.Type == b.Type
			}
			if diff := cmp.Diff(got, want, cmp.Comparer(fieldCmp)); diff != "" {
				t.Errorf("unexpected layer def (-got+want):\n%s", diff)
			}
			break
		}
		if !found {
			t.Errorf("layer %s (%s) not found", guid, windows.GUID(guid))
		}
	}
}

func TestSublayers(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(&Options{
		Dynamic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	sl := &Sublayer{
		ID:           guid,
		Name:         "test sublayer",
		Description:  "a test sublayer",
		ProviderData: []byte("byte blob"),
		Weight:       0x4242,
	}
	if err := s.AddSublayer(sl); err != nil {
		t.Fatalf("add sublayer failed: %v", err)
	}

	sublayers, err := s.Sublayers(nil)
	if err != nil {
		t.Fatalf("get sublayers failed: %v", err)
	}

	found := false
	for _, got := range sublayers {
		if got.ID != sl.ID {
			continue
		}
		found = true
		if diff := cmp.Diff(got, sl); diff != "" {
			t.Fatalf("sublayer is wrong (-got+want):\n%s", diff)
		}
		break
	}
	if !found {
		t.Fatal("sublayer added but not found")
	}

	if err := s.DeleteSublayer(sl.ID); err != nil {
		t.Fatalf("delete sublayer failed: %v", err)
	}

	sublayers, err = s.Sublayers(nil)
	if err != nil {
		t.Fatalf("get sublayers failed: %v", err)
	}
	for _, got := range sublayers {
		if got.ID == sl.ID {
			t.Fatalf("deleted sublayer but it's still there: %#v", got)
		}
	}
}

func TestProviders(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(&Options{
		Dynamic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	p := &Provider{
		ID:          guid,
		Name:        "test provider",
		Description: "a test provider",
		Data:        []byte("byte blob"),
	}
	if err := s.AddProvider(p); err != nil {
		t.Fatalf("add provider failed: %v", err)
	}

	providers, err := s.Providers()
	if err != nil {
		t.Fatalf("get providers failed: %v", err)
	}

	found := false
	for _, got := range providers {
		if got.ID != p.ID {
			continue
		}
		found = true
		if diff := cmp.Diff(got, p); diff != "" {
			t.Fatalf("provider is wrong (-got+want):\n%s", diff)
		}
		break
	}
	if !found {
		t.Fatal("provider added but not found")
	}

	if err := s.DeleteProvider(p.ID); err != nil {
		t.Fatalf("delete provider failed: %v", err)
	}

	providers, err = s.Providers()
	if err != nil {
		t.Fatalf("get providers failed: %v", err)
	}
	for _, got := range providers {
		if got.ID == p.ID {
			t.Fatalf("deleted provider but it's still there: %#v", got)
		}
	}
}
