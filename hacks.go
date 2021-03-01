package wf

import (
	"errors"
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

type FilterEnumType uint32

const (
	FilterEnumTypeFullyContained FilterEnumType = iota
	FilterEnumTypeOverlapping
)

type FilterEnumFlags uint32

const (
	FilterEnumFlagsBestTerminatingMatch FilterEnumFlags = iota + 1
	FilterEnumFlagsSorted
	FilterEnumFlagsBootTimeOnly
	FilterEnumFlagsIncludeBootTime
	FilterEnumFlagsIncludeDisabled
)

type ActionType uint32

const (
	ActionTypeBlock              ActionType = 0x1001
	ActionTypePermit             ActionType = 0x1002
	ActionTypeCalloutTerminating ActionType = 0x5003
	ActionTypeCalloutInspection  ActionType = 0x6004
	ActionTypeCalloutUnknown     ActionType = 0x4005
)

type MatchType uint32

const (
	MatchEqual MatchType = iota
	MatchGreater
	MatchLess
	MatchGreaterOrEqual
	MatchLessOrEqual
	MatchRange
	MatchFlagsAllSet
	MatchFlagsAnySet
	MatchFlagsNoneSet
	MatchEqualCaseInsensitive
	MatchNotEqual
	MatchPrefix
	MatchNotPrefix
)

type FilterFlags uint32

const (
	FilterFlagsPersistent FilterFlags = 1 << iota
	FilterFlagsBootTime
	FilterFlagsHasProviderContext
	FilterFlagsClearActionRight
	FilterFlagsPermitIfCalloutUnregistered
	FilterFlagsDisabled
	FilterFlagsIndexed
)

type Filter struct {
	Key                windows.GUID
	Name               string
	Description        string
	Flags              FilterFlags
	ProviderKey        *windows.GUID
	ProviderData       []byte
	LayerKey           windows.GUID
	SubLayerKey        windows.GUID
	Weight             Value
	Conditions         []Condition
	Action             Action
	ProviderContextKey windows.GUID
	Reserved           *windows.GUID
	FilterID           uint64
	EffectiveWeight    Value
}

type Condition struct {
	Field windows.GUID
	Op    MatchType
	Value Value
}

type Action struct {
	Type ActionType
	GUID windows.GUID
}

func (s *Session) Filters() ([]*Filter, error) {
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		fmt.Printf("%T\n", err)
		panic(err)
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*Filter

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

		for _, filter := range filters {
			f := &Filter{
				Key:                filter.FilterKey,
				Name:               windows.UTF16PtrToString(filter.DisplayData.Name),
				Description:        windows.UTF16PtrToString(filter.DisplayData.Description),
				Flags:              filter.Flags,
				ProviderKey:        filter.ProviderKey,
				ProviderData:       getByteBlob(filter.ProviderData),
				LayerKey:           filter.LayerKey,
				SubLayerKey:        filter.SubLayerKey,
				Weight:             nil, // TODO,
				Conditions:         nil, // TODO
				Action:             filter.Action,
				ProviderContextKey: filter.ProviderContextKey,
				FilterID:           filter.FilterID,
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

func (s *Session) AddProvider(provider *Provider) error {
	if provider.Key == (windows.GUID{}) {
		return errors.New("Provider.Key cannot be zero")
	}

	p := &fwpmProvider0{
		ProviderKey: provider.Key,
		DisplayData: mkDisplayData(provider.Name, provider.Description),
		//Flags:        provider.Flags,
		//ProviderData: mkByteBlob(provider.ProviderData),
		ServiceName: windows.StringToUTF16Ptr(provider.ServiceName),
	}

	return fwpmProviderAdd0(s.handle, p, nil)
}

func (s *Session) DeleteProvider(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmProviderDeleteByKey0(s.handle, &id)
}

type DataType uint32

const (
	DataTypeEmpty DataType = iota
	DataTypeUint8
	DataTypeUint16
	DataTypeUint32
	DataTypeUint64
	DataTypeInt8
	DataTypeInt16
	DataTypeInt32
	DataTypeInt64
	DataTypeFloat
	DataTypeDouble
	DataTypeByteArray16
	DataTypeByteBlob
	DataTypeSID
	DataTypeSecurityDescriptor
	DataTypeTokenInformation
	DataTypeTokenAccessInformation
	DataTypeUnicodeString
	DataTypeArray6
	DataTypeBitmapIndex
	DataTypeBitmapArray64
	DataTypeV4AddrMask DataType = 0x100 + iota
	DataTypeV6AddrMask
	DataTypeRange
)

type Value interface{}

func ValueValid(v Value) bool {
	switch v.(type) {
	case uint8, uint16, uint32, uint64, int8, int16, int32, int64, float32, float64, []byte, string, netaddr.IPPrefix:
		return true
	default:
		return false
	}
}

func valueToValue0(v Value) (ret fwpValue0, ref interface{}) {
	switch v.(type) {
	case netaddr.IPPrefix:
		return
	default:
		fc, ref := valueToFilterConditionValue0(v)
		return fwpValue0{fc.Type, fc.Value}, ref
	}
}

func valueToFilterConditionValue0(v Value) (ret fwpConditionValue0, ref interface{}) {
	if !ValueValid(v) {
		return
	}
	switch c := v.(type) {
	case uint8:
		ret.Type = DataTypeUint8
		*(*uint8)(unsafe.Pointer(&ret.Value)) = c
	case uint16:
		ret.Type = DataTypeUint16
		*(*uint16)(unsafe.Pointer(&ret.Value)) = c
	case uint32:
		ret.Type = DataTypeUint32
		*(*uint32)(unsafe.Pointer(&ret.Value)) = c
	case uint64:
		ret.Type = DataTypeUint64
		up := &c
		ref = up
		ret.Value = uintptr(unsafe.Pointer(up))
	case int8:
		ret.Type = DataTypeInt8
		*(*int8)(unsafe.Pointer(&ret.Value)) = c
	case int16:
		ret.Type = DataTypeInt16
		*(*int16)(unsafe.Pointer(&ret.Value)) = c
	case int32:
		ret.Type = DataTypeInt32
		*(*int32)(unsafe.Pointer(&ret.Value)) = c
	case int64:
		ret.Type = DataTypeInt64
		up := &c
		ref = up
		ret.Value = uintptr(unsafe.Pointer(up))
	case float32:
		ret.Type = DataTypeFloat
		*(*float32)(unsafe.Pointer(&ret.Value)) = c
	case float64:
		ret.Type = DataTypeDouble
		dp := &c
		ref = dp
		ret.Value = uintptr(unsafe.Pointer(dp))
	case []byte:
		ret.Type = DataTypeByteBlob
		bb := mkByteBlob(c)
		ref = &bb
		ret.Value = uintptr(unsafe.Pointer(&bb))
	case string:
		ret.Type = DataTypeUnicodeString
		s := windows.StringToUTF16Ptr(c)
		ref = s
		ret.Value = uintptr(unsafe.Pointer(s))
	case netaddr.IPPrefix:
		if c.IP.Is4() {
			ret.Type = DataTypeV4AddrMask
			ip4 := c.IP.As4()
			m4 := net.CIDRMask(int(c.Bits), 32)
			pfx := &fwpV4AddrAndMask{
				Addr: *(*uint32)(unsafe.Pointer(&ip4[0])),
				Mask: *(*uint32)(unsafe.Pointer(&m4[0])),
			}
			ref = pfx
			ret.Value = uintptr(unsafe.Pointer(pfx))
		} else {
			ret.Type = DataTypeV6AddrMask
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

func mkValue(typ DataType, v uintptr) Value {
	switch typ {
	case DataTypeUint8:
		return *(*uint8)(unsafe.Pointer(&v))
	case DataTypeUint16:
		return *(*uint16)(unsafe.Pointer(&v))
	case DataTypeUint32:
		return *(*uint32)(unsafe.Pointer(&v))
	case DataTypeUint64:
		return *(*uint64)(unsafe.Pointer(v))
	case DataTypeInt8:
		return *(*int8)(unsafe.Pointer(&v))
	case DataTypeInt16:
		return *(*int16)(unsafe.Pointer(&v))
	case DataTypeInt32:
		return *(*int32)(unsafe.Pointer(&v))
	case DataTypeInt64:
		return *(*int64)(unsafe.Pointer(v))
	case DataTypeFloat:
		return *(*float32)(unsafe.Pointer(&v))
	case DataTypeDouble:
		return *(*float64)(unsafe.Pointer(v))
	case DataTypeByteBlob:
		bb := (*fwpByteBlob)(unsafe.Pointer(v))
		return getByteBlob(*bb)
	case DataTypeUnicodeString:
		s := (*uint16)(unsafe.Pointer(v))
		return windows.UTF16PtrToString(s)
	case DataTypeV4AddrMask:
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
	case DataTypeV6AddrMask:
		pfx := (*fwpV6AddrAndMask)(unsafe.Pointer(v))
		return netaddr.IPPrefix{
			IP:   netaddr.IPFrom16(pfx.Addr),
			Bits: pfx.PrefixLength,
		}
	default:
		panic("unhandled type")
	}
}
