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
		guidLayerALEAuthRecvAcceptV4: {
			Key:                guidLayerALEAuthRecvAcceptV4,
			KernelID:           44,
			Name:               "ALE Receive/Accept v4 Layer",
			InKernel:           true,
			ClassifyMostly:     true,
			Buffered:           false,
			DefaultSublayerKey: guidSublayerUniversal,
			Fields: []*Field{
				{guidConditionALEAppID, stringT},
				{guidConditionALENapContext, u32T},
				{guidConditionALEPackageID, sidT},
				{guidConditionALERemoteMachineID, taiT},
				{guidConditionALERemoteUserID, taiT},
				{guidConditionALESecurityAttributeFqbnValue, bytesT},
				{guidConditionALESioFirewallSystemPort, u32T},
				{guidConditionALEUserID, taiT},
				{guidConditionArrivalInterfaceIndex, u32T},
				{guidConditionArrivalInterfaceType, u32T},
				{guidConditionArrivalTunnelType, u32T},
				{guidConditionBitmapIPLocalAddress, indexT},
				{guidConditionBitmapIPLocalPort, indexT},
				{guidConditionBitmapIPRemoteAddress, indexT},
				{guidConditionBitmapIPRemotePort, indexT},
				{guidConditionCompartmentID, u32T},
				{guidConditionCurrentProfileID, u32T},
				{guidConditionFlags, u32T},
				{guidConditionInterfaceIndex, u32T},
				{guidConditionInterfaceQuarantineEpoch, u64T},
				{guidConditionInterfaceType, u32T},
				{guidConditionIPArrivalInterface, u64T},
				{guidConditionIPLocalAddress, ipT},
				{guidConditionIPLocalAddressType, u8T},
				{guidConditionIPLocalInterface, u64T},
				{guidConditionIPLocalPort, u16T},
				{guidConditionIPNexthopInterface, u64T},
				{guidConditionIPProtocol, u8T},
				{guidConditionIPRemoteAddress, ipT},
				{guidConditionIPRemotePort, u16T},
				{guidConditionNexthopInterfaceIndex, u32T},
				{guidConditionNexthopInterfaceType, u32T},
				{guidConditionNexthopSubInterfaceIndex, u32T},
				{guidConditionNexthopTunnelType, u32T},
				{guidConditionOriginalICMPType, u16T},
				{guidConditionOriginalProfileID, u32T},
				{guidConditionReauthorizeReason, u32T},
				{guidConditionSubInterfaceIndex, u32T},
				{guidConditionTunnelType, u32T},
			},
		},
		guidLayerStreamV4Discard: {
			Key:                guidLayerStreamV4Discard,
			KernelID:           21,
			Name:               "Stream v4 Discard Layer",
			InKernel:           true,
			ClassifyMostly:     true,
			Buffered:           true,
			DefaultSublayerKey: guidSublayerUniversal,
			Fields: []*Field{
				{guidConditionCompartmentID, u32T},
				{guidConditionDirection, u32T},
				{guidConditionFlags, u32T},
				{guidConditionIPLocalAddress, ipT},
				{guidConditionIPLocalAddressType, u8T},
				{guidConditionIPLocalPort, u16T},
				{guidConditionIPRemoteAddress, ipT},
				{guidConditionIPRemotePort, u16T},
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
