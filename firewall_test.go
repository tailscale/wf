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
		opts *SessionOptions
	}{
		{
			name: "nil",
			opts: nil,
		},
		{
			name: "name_only",
			opts: &SessionOptions{
				Name: "test",
			},
		},
		{
			name: "name_and_desc",
			opts: &SessionOptions{
				Name:        "test2",
				Description: "unit test session",
			},
		},
		{
			name: "dynamic",
			opts: &SessionOptions{
				Name:    "test2",
				Dynamic: true,
			},
		},
		{
			name: "tx_timeout",
			opts: &SessionOptions{
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
	wantLayers := map[windows.GUID]*Layer{
		guidLayerALEAuthRecvAcceptV4: &Layer{
			Key:                guidLayerALEAuthRecvAcceptV4,
			Name:               "ALE Receive/Accept v4 Layer",
			InKernel:           true,
			ClassifyMostly:     true,
			Buffered:           false,
			DefaultSublayerKey: guidSublayerUniversal,
			Fields: []*Field{
				&Field{guidConditionALEAppID, stringT},
				&Field{guidConditionALENapContext, u32T},
				&Field{guidConditionALEPackageID, sidT},
				&Field{guidConditionALERemoteMachineID, taiT},
				&Field{guidConditionALERemoteUserID, taiT},
				&Field{guidConditionALESecurityAttributeFqbnValue, bytesT},
				&Field{guidConditionALESioFirewallSystemPort, u32T},
				&Field{guidConditionALEUserID, taiT},
				&Field{guidConditionArrivalInterfaceIndex, u32T},
				&Field{guidConditionArrivalInterfaceType, u32T},
				&Field{guidConditionArrivalTunnelType, u32T},
				&Field{guidConditionBitmapIPLocalAddress, indexT},
				&Field{guidConditionBitmapIPLocalPort, indexT},
				&Field{guidConditionBitmapIPRemoteAddress, indexT},
				&Field{guidConditionBitmapIPRemotePort, indexT},
				&Field{guidConditionCompartmentID, u32T},
				&Field{guidConditionCurrentProfileID, u32T},
				&Field{guidConditionFlags, u32T},
				&Field{guidConditionInterfaceIndex, u32T},
				&Field{guidConditionInterfaceQuarantineEpoch, u64T},
				&Field{guidConditionInterfaceType, u32T},
				&Field{guidConditionIPArrivalInterface, u64T},
				&Field{guidConditionIPLocalAddress, ipT},
				&Field{guidConditionIPLocalAddressType, u8T},
				&Field{guidConditionIPLocalInterface, u64T},
				&Field{guidConditionIPLocalPort, u16T},
				&Field{guidConditionIPNexthopInterface, u64T},
				&Field{guidConditionIPProtocol, u8T},
				&Field{guidConditionIPRemoteAddress, ipT},
				&Field{guidConditionIPRemotePort, u16T},
				&Field{guidConditionNexthopInterfaceIndex, u32T},
				&Field{guidConditionNexthopInterfaceType, u32T},
				&Field{guidConditionNexthopSubInterfaceIndex, u32T},
				&Field{guidConditionNexthopTunnelType, u32T},
				&Field{guidConditionOriginalICMPType, u16T},
				&Field{guidConditionOriginalProfileID, u32T},
				&Field{guidConditionReauthorizeReason, u32T},
				&Field{guidConditionSubInterfaceIndex, u32T},
				&Field{guidConditionTunnelType, u32T},
			},
		},
		guidLayerStreamV4Discard: &Layer{
			Key:                guidLayerStreamV4Discard,
			Name:               "Stream v4 Discard Layer",
			InKernel:           true,
			ClassifyMostly:     true,
			Buffered:           true,
			DefaultSublayerKey: guidSublayerUniversal,
			Fields: []*Field{
				&Field{guidConditionCompartmentID, u32T},
				&Field{guidConditionDirection, u32T},
				&Field{guidConditionFlags, u32T},
				&Field{guidConditionIPLocalAddress, ipT},
				&Field{guidConditionIPLocalAddressType, u8T},
				&Field{guidConditionIPLocalPort, u16T},
				&Field{guidConditionIPRemoteAddress, ipT},
				&Field{guidConditionIPRemotePort, u16T},
			},
		},
	}

	for guid, want := range wantLayers {
		found := false
		for _, got := range layers {
			if got.Key != guid {
				continue
			}
			found = true
			sort.Slice(got.Fields, func(i, j int) bool {
				return GUIDName(got.Fields[i].Key) < GUIDName(got.Fields[j].Key)
			})
			fieldCmp := func(a, b *Field) bool {
				return a.Key == b.Key && a.Type == b.Type
			}
			if diff := cmp.Diff(got, want, cmp.Comparer(fieldCmp)); diff != "" {
				t.Errorf("unexpected layer def (-got+want):\n%s", diff)
			}
			break
		}
		if !found {
			t.Errorf("layer %s (%s) not found", guid, GUIDName(guid))
		}
	}
}
