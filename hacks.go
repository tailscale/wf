package wf

import (
	"fmt"
	"math/bits"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

// This file is all the stuff I hacked on late at night, which needs
// cleaning up before it's up to actual publication standards.

func mkDisplayData(name, description string) fwpmDisplayData0 {
	return fwpmDisplayData0{
		Name:        windows.StringToUTF16Ptr(name),
		Description: windows.StringToUTF16Ptr(description),
	}
}

func mkByteBlob(bs []byte) fwpByteBlob {
	if len(bs) == 0 {
		return fwpByteBlob{0, nil}
	}
	return fwpByteBlob{
		Size: uint32(len(bs)),
		Data: &bs[0],
	}
}

func getByteBlob(bb fwpByteBlob) []byte {
	if bb.Size == 0 {
		return nil
	}

	var blob []uint8
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size)
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))
	return append([]byte(nil), blob...)
}

type filterEnumType uint32

const (
	filterEnumTypeFullyContained filterEnumType = iota
	filterEnumTypeOverlapping
)

type filterEnumFlags uint32

const (
	filterEnumFlagsBestTerminatingMatch filterEnumFlags = iota + 1
	filterEnumFlagsSorted
	filterEnumFlagsBootTimeOnly
	filterEnumFlagsIncludeBootTime
	filterEnumFlagsIncludeDisabled
)

type filter struct {
	Key                windows.GUID
	Name               string
	Description        string
	Flags              fwpmFilterFlags
	ProviderKey        *windows.GUID
	ProviderData       []byte
	LayerKey           windows.GUID
	SubLayerKey        windows.GUID
	Weight             value
	Conditions         []condition
	Action             Action
	ProviderContextKey windows.GUID
	Reserved           *windows.GUID
	FilterID           uint64
	EffectiveWeight    value
}

type condition struct {
	Field windows.GUID
	Op    MatchType
	value value
}

func (s *Session) filters() ([]*filter, error) {
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		fmt.Printf("%T\n", err)
		panic(err)
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*filter

	const pageSize = 100
	for {
		var filtersArray **fwpmFilter0
		var num uint32
		if err := fwpmFilterEnum0(s.handle, enum, pageSize, &filtersArray, &num); err != nil {
			panic(err)
			return nil, err
		}

		var filters []*fwpmFilter0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&filters))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(filtersArray))

		for _, filterv := range filters {
			f := &filter{
				Key:                filterv.FilterKey,
				Name:               windows.UTF16PtrToString(filterv.DisplayData.Name),
				Description:        windows.UTF16PtrToString(filterv.DisplayData.Description),
				Flags:              filterv.Flags,
				ProviderKey:        filterv.ProviderKey,
				ProviderData:       getByteBlob(filterv.ProviderData),
				LayerKey:           filterv.LayerKey,
				SubLayerKey:        filterv.SublayerKey,
				Weight:             nil, // TODO,
				Conditions:         nil, // TODO
				Action:             filterv.Action.Type,
				ProviderContextKey: filterv.ProviderContextKey,
				FilterID:           filterv.FilterID,
				EffectiveWeight:    nil, // TODO
			}
			ret = append(ret, f)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&filtersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

type value interface{}

func valueValid(v value) bool {
	switch v.(type) {
	case uint8, uint16, uint32, uint64, int8, int16, int32, int64, float32, float64, []byte, string, netaddr.IPPrefix:
		return true
	default:
		return false
	}
}

func valueToValue0(v value) (ret fwpValue0, ref interface{}) {
	switch v.(type) {
	case netaddr.IPPrefix:
		return
	default:
		fc, ref := valueToFilterConditionValue0(v)
		return fwpValue0{fc.Type, fc.Value}, ref
	}
}

func valueToFilterConditionValue0(v value) (ret fwpConditionValue0, ref interface{}) {
	if !valueValid(v) {
		return
	}
	switch c := v.(type) {
	case uint8:
		ret.Type = dataTypeUint8
		*(*uint8)(unsafe.Pointer(&ret.Value)) = c
	case uint16:
		ret.Type = dataTypeUint16
		*(*uint16)(unsafe.Pointer(&ret.Value)) = c
	case uint32:
		ret.Type = dataTypeUint32
		*(*uint32)(unsafe.Pointer(&ret.Value)) = c
	case uint64:
		ret.Type = dataTypeUint64
		up := &c
		ref = up
		ret.Value = uintptr(unsafe.Pointer(up))
	case int8:
		ret.Type = dataTypeInt8
		*(*int8)(unsafe.Pointer(&ret.Value)) = c
	case int16:
		ret.Type = dataTypeInt16
		*(*int16)(unsafe.Pointer(&ret.Value)) = c
	case int32:
		ret.Type = dataTypeInt32
		*(*int32)(unsafe.Pointer(&ret.Value)) = c
	case int64:
		ret.Type = dataTypeInt64
		up := &c
		ref = up
		ret.Value = uintptr(unsafe.Pointer(up))
	case float32:
		ret.Type = dataTypeFloat
		*(*float32)(unsafe.Pointer(&ret.Value)) = c
	case float64:
		ret.Type = dataTypeDouble
		dp := &c
		ref = dp
		ret.Value = uintptr(unsafe.Pointer(dp))
	case []byte:
		ret.Type = dataTypeByteBlob
		bb := mkByteBlob(c)
		ref = &bb
		ret.Value = uintptr(unsafe.Pointer(&bb))
	case string:
		ret.Type = dataTypeUnicodeString
		s := windows.StringToUTF16Ptr(c)
		ref = s
		ret.Value = uintptr(unsafe.Pointer(s))
	case netaddr.IPPrefix:
		if c.IP.Is4() {
			ret.Type = dataTypeV4AddrMask
			ip4 := c.IP.As4()
			m4 := net.CIDRMask(int(c.Bits), 32)
			pfx := &fwpV4AddrAndMask{
				Addr: *(*uint32)(unsafe.Pointer(&ip4[0])),
				Mask: *(*uint32)(unsafe.Pointer(&m4[0])),
			}
			ref = pfx
			ret.Value = uintptr(unsafe.Pointer(pfx))
		} else {
			ret.Type = dataTypeV6AddrMask
			pfx := &fwpV6AddrAndMask{
				PrefixLength: c.Bits,
			}
			ip6 := c.IP.As16()
			copy(pfx.Addr[:], ip6[:])
			ref = pfx
			ret.Value = uintptr(unsafe.Pointer(pfx))
		}
	}

	return ret, ref
}

func mkValue(typ dataType, v uintptr) value {
	switch typ {
	case dataTypeUint8:
		return *(*uint8)(unsafe.Pointer(&v))
	case dataTypeUint16:
		return *(*uint16)(unsafe.Pointer(&v))
	case dataTypeUint32:
		return *(*uint32)(unsafe.Pointer(&v))
	case dataTypeUint64:
		return *(*uint64)(unsafe.Pointer(v))
	case dataTypeInt8:
		return *(*int8)(unsafe.Pointer(&v))
	case dataTypeInt16:
		return *(*int16)(unsafe.Pointer(&v))
	case dataTypeInt32:
		return *(*int32)(unsafe.Pointer(&v))
	case dataTypeInt64:
		return *(*int64)(unsafe.Pointer(v))
	case dataTypeFloat:
		return *(*float32)(unsafe.Pointer(&v))
	case dataTypeDouble:
		return *(*float64)(unsafe.Pointer(v))
	case dataTypeByteBlob:
		bb := (*fwpByteBlob)(unsafe.Pointer(v))
		return getByteBlob(*bb)
	case dataTypeUnicodeString:
		s := (*uint16)(unsafe.Pointer(v))
		return windows.UTF16PtrToString(s)
	case dataTypeV4AddrMask:
		pfx := (*fwpV4AddrAndMask)(unsafe.Pointer(v))
		bits := 32 - bits.TrailingZeros32(pfx.Mask)
		var vs []byte
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&vs[0]))
		sh.Cap = 4
		sh.Len = 4
		sh.Data = uintptr(unsafe.Pointer(&pfx.Addr))
		ip := netaddr.IPv4(vs[0], vs[1], vs[2], vs[3])
		return netaddr.IPPrefix{
			IP:   ip,
			Bits: uint8(bits),
		}
	case dataTypeV6AddrMask:
		pfx := (*fwpV6AddrAndMask)(unsafe.Pointer(v))
		return netaddr.IPPrefix{
			IP:   netaddr.IPFrom16(pfx.Addr),
			Bits: pfx.PrefixLength,
		}
	default:
		panic("unhandled type")
	}
}
