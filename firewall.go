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

type Session struct {
	handle windows.Handle
}

func New() (*Session, error) {
	session := fwpmSession0{
		DisplayData: fwpmDisplayData0{
			Name:        windows.StringToUTF16Ptr("test"),
			Description: windows.StringToUTF16Ptr("test description"),
		},
		Flags:                fwpmSession0FlagDynamic,
		TxnWaitTimeoutMillis: windows.INFINITE,
	}

	var handle windows.Handle

	err := fwpmEngineOpen0(nil, authnServiceWinNT, nil, &session, &handle)
	if err != nil {
		return nil, err
	}

	return &Session{
		handle: handle,
	}, nil
}

func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	return fwpmEngineClose0(s.handle)
}

// LayerFlags are flags associated with a layer.
type LayerFlags uint32

const (
	LayerFlagsKernel         LayerFlags = 1 << iota // classification occurs in kernel mode
	LayerFlagsBuiltin                               // built-in layer, cannot be deleted
	LayerFlagsClassifyMostly                        // optimized for classifying not enumerating
	LayerFlagsBuffered                              // buffered?
)

type FieldType uint32

const (
	FieldTypeRawData FieldType = iota
	FieldTypeIPAddress
	FieldTypeFlags
)

type SublayerFlags uint32

const SublayerFlagsPersistent SublayerFlags = 1

type Layer struct {
	Key                windows.GUID
	ID                 uint16
	Name               string
	Description        string
	Flags              LayerFlags
	DefaultSublayerKey windows.GUID
	Fields             []*Field
}

type Field struct {
	Key      windows.GUID
	Type     FieldType
	DataType DataType
}

func (s *Session) Layers() ([]*Layer, error) {
	var enum windows.Handle
	if err := fwpmLayerCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Layer

	const pageSize = 100
	for {
		var layersArray **fwpmLayer0
		var num uint32
		if err := fwpmLayerEnum0(s.handle, enum, pageSize, &layersArray, &num); err != nil {
			return nil, err
		}

		var layers []*fwpmLayer0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(layersArray))

		for _, layer := range layers {
			var fields []fwpmField0
			sh = (*reflect.SliceHeader)(unsafe.Pointer(&fields))
			sh.Cap = int(layer.NumFields)
			sh.Len = int(layer.NumFields)
			sh.Data = uintptr(unsafe.Pointer(layer.Fields))

			l := &Layer{
				Key:                layer.LayerKey,
				ID:                 layer.LayerID,
				Name:               windows.UTF16PtrToString(layer.DisplayData.Name),
				Description:        windows.UTF16PtrToString(layer.DisplayData.Description),
				Flags:              layer.Flags,
				DefaultSublayerKey: layer.DefaultSublayerKey,
			}
			for _, field := range fields {
				l.Fields = append(l.Fields, &Field{
					Key:      *field.FieldKey,
					Type:     field.Type,
					DataType: field.DataType,
				})
			}
			ret = append(ret, l)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&layersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

type Sublayer struct {
	Key          windows.GUID
	Name         string
	Description  string
	Flags        SublayerFlags
	Provider     *windows.GUID // optional
	ProviderData []byte
	Weight       uint16
}

func (s *Session) Sublayers(provider *windows.GUID) ([]*Sublayer, error) {
	tpl := fwpmSublayerEnumTemplate0{
		ProviderKey: provider,
	}

	var enum windows.Handle
	if err := fwpmSubLayerCreateEnumHandle0(s.handle, &tpl, &enum); err != nil {
		return nil, err
	}
	defer fwpmSubLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Sublayer

	const pageSize = 100
	for {
		var sublayersArray **fwpmSublayer0
		var num uint32
		if err := fwpmSubLayerEnum0(s.handle, enum, pageSize, &sublayersArray, &num); err != nil {
			return nil, err
		}

		var sublayers []*fwpmSublayer0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&sublayers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(sublayersArray))

		for _, sublayer := range sublayers {
			l := &Sublayer{
				Key:          sublayer.SublayerKey,
				Name:         windows.UTF16PtrToString(sublayer.DisplayData.Name),
				Description:  windows.UTF16PtrToString(sublayer.DisplayData.Description),
				Flags:        sublayer.Flags,
				Provider:     sublayer.ProviderKey,
				ProviderData: getByteBlob(sublayer.ProviderData),
				Weight:       sublayer.Weight,
			}
			ret = append(ret, l)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&sublayersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

func (s *Session) AddSublayer(sublayer *Sublayer) error {
	if sublayer.Key == (windows.GUID{}) {
		return errors.New("Sublayer.Key cannot be zero")
	}

	sl := fwpmSublayer0{
		SublayerKey:  sublayer.Key,
		DisplayData:  mkDisplayData(sublayer.Name, sublayer.Description),
		Flags:        sublayer.Flags,
		ProviderKey:  sublayer.Provider,
		ProviderData: mkByteBlob(sublayer.ProviderData),
		Weight:       sublayer.Weight,
	}

	return fwpmSubLayerAdd0(s.handle, &sl, nil)
}

func (s *Session) DeleteSublayer(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmSubLayerDeleteByKey0(s.handle, &id)
}

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

type ProviderFlags uint32

const (
	ProviderFlagsPersistent ProviderFlags = 0x01
	ProviderFlagsDisabled   ProviderFlags = 0x10
)

type Provider struct {
	Key          windows.GUID
	Name         string
	Description  string
	Flags        ProviderFlags
	ProviderData []byte
	ServiceName  string
}

func (s *Session) Providers() ([]*Provider, error) {
	var enum windows.Handle
	if err := fwpmProviderCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmProviderDestroyEnumHandle0(s.handle, enum)

	var ret []*Provider

	const pageSize = 100
	for {
		var providersArray **fwpmProvider0
		var num uint32
		if err := fwpmProviderEnum0(s.handle, enum, pageSize, &providersArray, &num); err != nil {
			return nil, err
		}

		var providers []*fwpmProvider0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&providers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(providersArray))

		for _, provider := range providers {
			p := &Provider{
				Key:          provider.ProviderKey,
				Name:         windows.UTF16PtrToString(provider.DisplayData.Name),
				Description:  windows.UTF16PtrToString(provider.DisplayData.Description),
				Flags:        provider.Flags,
				ProviderData: getByteBlob(provider.ProviderData),
				ServiceName:  windows.UTF16PtrToString(provider.ServiceName),
			}
			ret = append(ret, p)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&providersArray)))

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
		ProviderKey:  provider.Key,
		DisplayData:  mkDisplayData(provider.Name, provider.Description),
		Flags:        provider.Flags,
		ProviderData: mkByteBlob(provider.ProviderData),
		ServiceName:  windows.StringToUTF16Ptr(provider.ServiceName),
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
	DataTypeV4AddrMask Datatype = 0x100 + iota
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
