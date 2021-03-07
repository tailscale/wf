package wf

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

func toSession0(a *arena, opts *SessionOptions) *fwpmSession0 {
	ret := (*fwpmSession0)(a.alloc(unsafe.Sizeof(fwpmSession0{})))
	*ret = fwpmSession0{
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, opts.Name),
			Description: toUint16(a, opts.Description),
		},
		TxnWaitTimeoutMillis: uint32(opts.TransactionStartTimeout.Milliseconds()),
	}
	if opts.Dynamic {
		ret.Flags = fwpmSession0FlagDynamic
	}
	return ret
}

func toSublayerEnumTemplate0(a *arena, provider *windows.GUID) *fwpmSublayerEnumTemplate0 {
	ret := (*fwpmSublayerEnumTemplate0)(a.alloc(unsafe.Sizeof(fwpmSublayerEnumTemplate0{})))
	ret.ProviderKey = toGUID(a, provider)
	return ret
}

func toSublayer0(a *arena, sl *Sublayer) *fwpmSublayer0 {
	ret := (*fwpmSublayer0)(a.alloc(unsafe.Sizeof(fwpmSublayer0{})))
	*ret = fwpmSublayer0{
		SublayerKey: sl.Key,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, sl.Name),
			Description: toUint16(a, sl.Description),
		},
		ProviderKey: toGUID(a, sl.Provider),
		ProviderData: fwpByteBlob{
			Size: uint32(len(sl.ProviderData)),
			Data: toBytes(a, sl.ProviderData),
		},
		Weight: sl.Weight,
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
		ProviderKey: toGUID(a, r.Provider),
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

	var conds []fwpmFilterCondition0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&conds))
	sh.Cap = len(ms)
	sh.Len = len(ms)
	sh.Data = uintptr(unsafe.Pointer(array))

	for i, m := range ms {
		c := &conds[i]

		typ, val, err := toValue0(a, m.Value, ft[m.Key])
		if err != nil {
			return nil, err
		}

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
	if len(s) == 0 {
		return nil
	}

	n := windows.StringToUTF16(s)
	ret := a.calloc(len(n), 2)

	var sl []uint16
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sl))
	sh.Cap = len(s)
	sh.Len = len(s)
	sh.Data = uintptr(ret)

	copy(sl, n)
	return (*uint16)(ret)
}

func toBytes(a *arena, bs []byte) *byte {
	if len(bs) == 0 {
		return nil
	}

	ret := a.calloc(len(bs), 1)

	var sl []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sl))
	sh.Cap = len(bs)
	sh.Len = len(bs)
	sh.Data = uintptr(ret)

	copy(sl, bs)
	return (*byte)(ret)
}

func toGUID(a *arena, guid *windows.GUID) *windows.GUID {
	if guid == nil {
		return nil
	}
	ret := (*windows.GUID)(a.alloc(unsafe.Sizeof(windows.GUID{})))
	*ret = *guid
	return ret
}
