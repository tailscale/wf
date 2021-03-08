package wf

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
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

	switch ftype {
	case reflect.TypeOf(uint8(0)):
		typ = dataTypeUint8
		u, ok := v.(uint8)
		if !ok {
			return mapErr()
		}
		*(*uint8)(unsafe.Pointer(&val)) = u
	case reflect.TypeOf(uint16(0)):
		typ = dataTypeUint16
		u, ok := v.(uint16)
		if !ok {
			return mapErr()
		}
		*(*uint16)(unsafe.Pointer(&val)) = u
	case reflect.TypeOf(uint32(0)):
		typ = dataTypeUint32
		u, ok := v.(uint32)
		if !ok {
			return mapErr()
		}
		*(*uint32)(unsafe.Pointer(&val)) = u
	case reflect.TypeOf(uint64(0)):
		typ = dataTypeUint64
		u, ok := v.(uint64)
		if !ok {
			return mapErr()
		}
		p := a.alloc(unsafe.Sizeof(u))
		*(*uint64)(p) = u
		val = uintptr(p)
	case reflect.TypeOf([]byte(nil)):
		typ = dataTypeByteBlob
		bb, ok := v.([]byte)
		if !ok {
			return mapErr()
		}

		p := a.alloc(unsafe.Sizeof(fwpByteBlob{}))
		*(*fwpByteBlob)(p) = fwpByteBlob{
			Size: uint32(len(bb)),
			Data: toBytes(a, bb),
		}
		val = uintptr(p)
	case reflect.TypeOf(&windows.SID{}):
		typ = dataTypeSID
		s, ok := v.(*windows.SID)
		if !ok {
			return mapErr()
		}
		sidLen := windows.GetLengthSid(s)
		p := a.alloc(uintptr(sidLen))
		if err := windows.CopySid(sidLen, (*windows.SID)(p), s); err != nil {
			return 0, 0, err
		}
		val = uintptr(p)
	case reflect.TypeOf(BitmapIndex(0)):
		typ = dataTypeBitmapIndex
		i, ok := v.(BitmapIndex)
		if !ok {
			return mapErr()
		}
		*(*uint8)(unsafe.Pointer(&val)) = uint8(i)
	case reflect.TypeOf([16]byte{}):
		typ = dataTypeByteArray16
		bs, ok := v.([16]byte)
		if !ok {
			return mapErr()
		}
		val = uintptr(unsafe.Pointer(toBytes(a, bs[:])))
	case reflect.TypeOf(net.HardwareAddr{}):
		typ = dataTypeArray6
		mac, ok := v.(net.HardwareAddr)
		if !ok {
			return mapErr()
		}
		if len(mac) != 6 {
			return mapErr() // TODO: better error
		}
		val = uintptr(unsafe.Pointer(toBytes(a, mac[:])))
	case reflect.TypeOf(netaddr.IP{}):
		switch m := v.(type) {
		case netaddr.IP:
			if m.Is4() {
				typ = dataTypeUint32
				*(*uint32)(unsafe.Pointer(&val)) = u32FromIPv4(m)
			} else {
				typ = dataTypeByteArray16
				b16 := m.As16()
				val = uintptr(unsafe.Pointer(toBytes(a, b16[:])))
			}
		case netaddr.IPPrefix:
			if m.IP.Is4() {
				typ = dataTypeV4AddrMask
				val = uintptr(unsafe.Pointer(toFwpV4AddrAndMask(a, m)))
			} else {
				typ = dataTypeV6AddrMask
				val = uintptr(unsafe.Pointer(toFwpV6AddrAndMask(a, m)))
			}
		case netaddr.IPRange:
			if !m.Valid() {
				return 0, 0, fmt.Errorf("invalid IPRange %v", m)
			}
			r, err := toRange0(a, m.From, m.To, ftype)
			if err != nil {
				return 0, 0, err
			}
			typ = dataTypeRange
			val = uintptr(unsafe.Pointer(r))
		}
	case reflect.TypeOf((*windows.SECURITY_DESCRIPTOR)(nil)):
		sd, ok := v.(*windows.SECURITY_DESCRIPTOR)
		if !ok {
			return mapErr()
		}
		csd, err := toSecurityDescriptor(a, sd)
		if err != nil {
			return 0, 0, err
		}
		typ = dataTypeSecurityDescriptor
		val = uintptr(unsafe.Pointer(csd))
	}

	// TODO: dataTypeTokenInformation
	// TODO: dataTypeTokenAccessInformation

	return typ, val, nil
}

func toRange0(a *arena, from, to interface{}, ftype reflect.Type) (ret *fwpRange0, err error) {
	if _, ok := from.(Range); ok {
		return nil, errors.New("can't have a Range of Ranges")
	}
	if _, ok := to.(Range); ok {
		return nil, errors.New("can't have a Range of Ranges")
	}

	ftyp, fval, err := toValue0(a, from, ftype)
	if err != nil {
		return nil, err
	}
	ttyp, tval, err := toValue0(a, to, ftype)
	if err != nil {
		return nil, err
	}
	ret = (*fwpRange0)(a.alloc(unsafe.Sizeof(fwpRange0{})))

	*ret = fwpRange0{
		From: fwpValue0{
			Type:  ftyp,
			Value: fval,
		},
		To: fwpValue0{
			Type:  ttyp,
			Value: tval,
		},
	}
	return ret, nil
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

func toFwpV4AddrAndMask(a *arena, pfx netaddr.IPPrefix) *fwpV4AddrAndMask {
	ret := (*fwpV4AddrAndMask)(a.alloc(unsafe.Sizeof(fwpV4AddrAndMask{})))
	ret.Addr = u32FromIPv4(pfx.Masked().IP)
	ret.Mask = (^uint32(0)) << (32 - pfx.Bits)
	return ret
}

func toFwpV6AddrAndMask(a *arena, pfx netaddr.IPPrefix) *fwpV6AddrAndMask {
	ret := (*fwpV6AddrAndMask)(a.alloc(unsafe.Sizeof(fwpV6AddrAndMask{})))
	ret.Addr = pfx.IP.As16()
	ret.PrefixLength = pfx.Bits
	return ret
}

func toSecurityDescriptor(a *arena, s *windows.SECURITY_DESCRIPTOR) (*windows.SECURITY_DESCRIPTOR, error) {
	s, err := s.ToSelfRelative()
	if err != nil {
		return nil, err
	}

	sl := s.Length()
	var from []byte
	sf := (*reflect.SliceHeader)(unsafe.Pointer(&from))
	sf.Cap = int(sl)
	sf.Len = int(sl)
	sf.Data = uintptr(unsafe.Pointer(s))

	p := a.alloc(uintptr(s.Length()))
	var to []byte
	st := (*reflect.SliceHeader)(unsafe.Pointer(&to))
	st.Cap = int(sl)
	st.Len = int(sl)
	st.Data = uintptr(p)

	copy(to, from)

	return (*windows.SECURITY_DESCRIPTOR)(p), nil
}

func u32FromIPv4(ip netaddr.IP) uint32 {
	b4 := ip.As4()
	return *(*uint32)(unsafe.Pointer(&b4[0]))
}
