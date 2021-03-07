package wf

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

func toSublayer0(a *arena, sl *Sublayer) *fwpmSublayer0 {
	ret := (*fwpmSublayer0)(a.alloc(unsafe.Sizeof(fwpmSublayer0{})))
	*ret = fwpmSublayer0{
		SublayerKey: sl.Key,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, sl.Name),
			Description: toUint16(a, sl.Description),
		},
		ProviderData: fwpByteBlob{
			Size: uint32(len(sl.ProviderData)),
			Data: toBytes(a, sl.ProviderData),
		},
		Weight: sl.Weight,
	}
	if sl.Provider != nil {
		guid := (*windows.GUID)(a.alloc(unsafe.Sizeof(windows.GUID{})))
		*guid = *sl.Provider
	}

	return ret
}

func toProvider0(a *arena, p *Provider) *fwpmProvider0 {
	ret := (*fwpmProvider0)(a.alloc(unsafe.Sizeof(fwpmProvider0{})))
	*ret = fwpmProvider0{
		ProviderKey: p.Key,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, p.Name),
			Description: toUint16(a, p.Description),
		},
		ProviderData: fwpByteBlob{
			Size: uint32(len(p.Data)),
			Data: toBytes(a, p.Data),
		},
		ServiceName: toUint16(a, p.ServiceName),
	}
	if p.Persistent {
		ret.Flags = fwpmProviderFlagsPersistent
	}

	return ret
}

func toFilter0(a *arena, r *Rule, lt layerTypes) (*fwpmFilter0, error) {
	conds, err := toCondition0(a, r.Conditions, lt[r.Layer])
	if err != nil {
		return nil, err
	}

	typ, val, err := toValue0(a, r.Weight, reflect.TypeOf(uint64(0)))
	if err != nil {
		return nil, err
	}

	ret := (*fwpmFilter0)(a.alloc(unsafe.Sizeof(fwpmFilter0{})))
	*ret = fwpmFilter0{
		FilterKey: r.Key,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, r.Name),
			Description: toUint16(a, r.Description),
		},
		ProviderKey: r.Provider,
		ProviderData: fwpByteBlob{
			Size: uint32(len(r.ProviderData)), // todo: overflow?
			Data: toBytes(a, r.ProviderData),
		},
		LayerKey:    r.Layer,
		SublayerKey: r.Sublayer,
		Weight: fwpValue0{
			Type:  typ,
			Value: val,
		},
		NumFilterConditions: uint32(len(r.Conditions)), // TODO: overflow?
		FilterConditions:    conds,
		Action: fwpmAction0{
			Type: r.Action,
			GUID: r.Callout,
		},
	}

	if r.PermitIfMissing {
		ret.Flags |= fwpmFilterFlagsPermitIfCalloutUnregistered
	}
	if r.Persistent {
		ret.Flags |= fwpmFilterFlagsPersistent
	}
	if r.BootTime {
		ret.Flags |= fwpmFilterFlagsBootTime
	}

	return ret, nil
}

func toCondition0(a *arena, ms []*Match, ft fieldTypes) (array *fwpmFilterCondition0, err error) {
	array = (*fwpmFilterCondition0)(a.calloc(len(ms), unsafe.Sizeof(fwpmFilterCondition0{})))

	for i, m := range ms {
		typ, val, err := toValue0(a, m.Value, ft[m.Key])
		if err != nil {
			return nil, err
		}

		c := (*fwpmFilterCondition0)(unsafe.Pointer(uintptr(unsafe.Pointer(array)) + uintptr(i)*unsafe.Sizeof(fwpmFilterCondition0{})))
		*c = fwpmFilterCondition0{
			FieldKey:  m.Key,
			MatchType: m.Op,
			Value: fwpConditionValue0{
				Type:  typ,
				Value: val,
			},
		}
	}

	return array, nil
}

func toValue0(a *arena, v interface{}, ftype reflect.Type) (typ dataType, val uintptr, err error) {
	mapErr := func() (dataType, uintptr, error) {
		return 0, 0, fmt.Errorf("can't map type %T into condition type %v", v, ftype)
	}

	// TODO: exceptions go here

	typ = fieldTypeMapReverse[ftype]
	switch typ {
	case dataTypeUint8:
		u, ok := v.(uint8)
		if !ok {
			return mapErr()
		}
		*(*uint8)(unsafe.Pointer(&val)) = u
	case dataTypeUint16:
		u, ok := v.(uint16)
		if !ok {
			return mapErr()
		}
		*(*uint16)(unsafe.Pointer(&val)) = u
	case dataTypeUint32:
		u, ok := v.(uint32)
		if !ok {
			return mapErr()
		}
		*(*uint32)(unsafe.Pointer(&val)) = u
	case dataTypeUint64:
		p := a.alloc(unsafe.Sizeof(uint64(0)))

		u, ok := v.(uint64)
		if !ok {
			return mapErr()
		}
		*(*uint64)(p) = u
		val = uintptr(p)
	case dataTypeByteBlob:
		u, ok := v.([]byte)
		if !ok {
			return mapErr()
		}

		p := a.alloc(unsafe.Sizeof(fwpByteBlob{}))
		*(*fwpByteBlob)(p) = fwpByteBlob{
			Size: uint32(len(u)), // todo: overflow
			Data: toBytes(a, u),
		}
		val = uintptr(p)
	case dataTypeSID:
		u, ok := v.(*windows.SID)
		if !ok {
			return mapErr()
		}

		sidLen := windows.GetLengthSid(u)
		p := a.alloc(uintptr(sidLen))
		if err := windows.CopySid(sidLen, (*windows.SID)(p), u); err != nil {
			return 0, 0, err
		}
		val = uintptr(p)
	}

	// TODO: bitmapIndex
	// TODO: dataTypeArray16
	// TODO: dataTypeArray6
	// TODO: dataTypeSecurityDescriptor
	// TODO: dataTypeTokenInformation
	// TODO: dataTypeTokenAccessInformation
	// TODO: addr masks

	return typ, val, nil
}

func toUint16(a *arena, s string) *uint16 {
	n := windows.StringToUTF16(s)
	np := a.calloc(len(n), 2)
	for i := range n {
		*(*uint16)(unsafe.Pointer(uintptr(np) + uintptr(i))) = n[i]
	}
	return (*uint16)(np)
}

func toBytes(a *arena, bs []byte) *byte {
	if len(bs) == 0 {
		return nil
	}
	p := a.calloc(len(bs), 1)
	for i := range bs {
		*(*byte)(unsafe.Pointer(uintptr(p) + uintptr(i))) = bs[i]
	}
	return (*byte)(p)
}
