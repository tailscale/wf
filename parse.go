package wf

import (
	"errors"
	"fmt"
	"math/bits"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

// This file contains parsing code for structures returned by the WFP
// API. These are the structs defined in types.go, allocated out of
// the C heap by WFP. The parsers in this file convert those raw
// structs (which require unsafe pointers to traverse) into safe Go
// types.

// fieldTypeMap maps dataType to a Go value of that type.
var fieldTypeMap = map[dataType]reflect.Type{
	dataTypeUint8:                  reflect.TypeOf(uint8(0)),
	dataTypeUint16:                 reflect.TypeOf(uint16(0)),
	dataTypeUint32:                 reflect.TypeOf(uint32(0)),
	dataTypeUint64:                 reflect.TypeOf(uint64(0)),
	dataTypeByteArray16:            reflect.TypeOf([16]byte{}),
	dataTypeByteBlob:               reflect.TypeOf([]byte(nil)),
	dataTypeSID:                    reflect.TypeOf(windows.SID{}),
	dataTypeSecurityDescriptor:     reflect.TypeOf(windows.SECURITY_DESCRIPTOR{}),
	dataTypeTokenInformation:       reflect.TypeOf(TokenInformation{}),
	dataTypeTokenAccessInformation: reflect.TypeOf(TokenAccessInformation(nil)),
	dataTypeArray6:                 reflect.TypeOf([6]byte{}),
	dataTypeBitmapIndex:            reflect.TypeOf(BitmapIndex(0)),
	dataTypeV4AddrMask:             reflect.TypeOf(netaddr.IPPrefix{}),
	dataTypeV6AddrMask:             reflect.TypeOf(netaddr.IPPrefix{}),
	dataTypeRange:                  reflect.TypeOf(Range{}),
}

// fieldType returns the reflect.Type for a field, or an error if the
// field has an unknown or infeasible type.
func fieldType(f *fwpmField0) (reflect.Type, error) {
	// IP addresses are represented as either a uint32 or a 16-byte
	// array, with a modifier flag indicating that it's an IP
	// address. Use plain IPs when exposing in Go.
	if f.Type == fwpmFieldTypeIPAddress {
		if f.DataType != dataTypeUint32 && f.DataType != dataTypeByteArray16 {
			return nil, fmt.Errorf("field has IP address type, but underlying datatype is %s (want Uint32 or ByteArray16)", f.DataType)
		}
		return reflect.TypeOf(netaddr.IP{}), nil
	}
	// Flags are a uint32 with a modifier. This just checks that there
	// are no surprise flag fields of other types.
	if f.Type == fwpmFieldTypeFlags {
		if f.DataType != dataTypeUint32 {
			return nil, fmt.Errorf("field has flag type, but underlying datatype is %s (want Uint32)", f.DataType)
		}
		return reflect.TypeOf(uint32(0)), nil
	}

	if t, ok := fieldTypeMap[f.DataType]; ok {
		return t, nil
	}

	return nil, fmt.Errorf("unknown data type %s", f.DataType)
}

// toLayers converts a C array of *fwpmLayer0 to a safe-to-use *Layer slice.
func fromLayer0(array **fwpmLayer0, num uint32) ([]*Layer, error) {
	var ret []*Layer

	var layers []*fwpmLayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, layer := range layers {
		l := &Layer{
			Key:                layer.LayerKey,
			Name:               windows.UTF16PtrToString(layer.DisplayData.Name),
			Description:        windows.UTF16PtrToString(layer.DisplayData.Description),
			InKernel:           (layer.Flags & fwpmLayerFlagsKernel) != 0,
			ClassifyMostly:     (layer.Flags & fwpmLayerFlagsClassifyMostly) != 0,
			Buffered:           (layer.Flags & fwpmLayerFlagsBuffered) != 0,
			DefaultSublayerKey: layer.DefaultSublayerKey,
		}

		var fields []fwpmField0
		sh = (*reflect.SliceHeader)(unsafe.Pointer(&fields))
		sh.Cap = int(layer.NumFields)
		sh.Len = int(layer.NumFields)
		sh.Data = uintptr(unsafe.Pointer(layer.Fields))

		for i := range fields {
			field := &fields[i]
			typ, err := fieldType(field)
			if err != nil {
				return nil, fmt.Errorf("finding type of field %s: %w", GUIDName(*field.FieldKey), err)
			}
			l.Fields = append(l.Fields, &Field{
				Key:  *field.FieldKey,
				Type: typ,
			})
		}

		ret = append(ret, l)
	}

	return ret, nil
}

// toSublayers converts a C array of *fwpmSublayer0 to a safe-to-use *Sublayer slice.
func fromSublayer0(array **fwpmSublayer0, num uint32) []*Sublayer {
	var ret []*Sublayer

	var sublayers []*fwpmSublayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sublayers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, sublayer := range sublayers {
		s := &Sublayer{
			Key:          sublayer.SublayerKey,
			Name:         windows.UTF16PtrToString(sublayer.DisplayData.Name),
			Description:  windows.UTF16PtrToString(sublayer.DisplayData.Description),
			Persistent:   (sublayer.Flags & fwpmSublayerFlagsPersistent) != 0,
			ProviderData: fromByteBlob(&sublayer.ProviderData),
			Weight:       sublayer.Weight,
		}
		if sublayer.ProviderKey != nil {
			// Make a copy of the GUID, to ensure we're not aliasing C
			// memory.
			p := *sublayer.ProviderKey
			s.Provider = &p
		}
		ret = append(ret, s)
	}

	return ret
}

// toProviders converts a C array of fwpmProvider0 to a safe-to-use Provider
// slice.
func fromProvider0(array **fwpmProvider0, num uint32) []*Provider {
	var ret []*Provider

	var providers []*fwpmProvider0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&providers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, provider := range providers {
		p := &Provider{
			Key:         provider.ProviderKey,
			Name:        windows.UTF16PtrToString(provider.DisplayData.Name),
			Description: windows.UTF16PtrToString(provider.DisplayData.Description),
			Persistent:  (provider.Flags & fwpmProviderFlagsPersistent) != 0,
			Disabled:    (provider.Flags & fwpmProviderFlagsDisabled) != 0,
			Data:        fromByteBlob(&provider.ProviderData),
			ServiceName: windows.UTF16PtrToString(provider.ServiceName),
		}
		ret = append(ret, p)
	}

	return ret
}

func fromFilter0(array **fwpmFilter0, num uint32, layerTypes layerTypes) ([]*Rule, error) {
	var rules []*fwpmFilter0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&rules))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	var ret []*Rule

	for _, rule := range rules {
		r := &Rule{
			Key:          rule.FilterKey,
			Name:         windows.UTF16PtrToString(rule.DisplayData.Name),
			Description:  windows.UTF16PtrToString(rule.DisplayData.Description),
			Layer:        rule.LayerKey,
			Sublayer:     rule.SublayerKey,
			Action:       rule.Action.Type,
			Persistent:   (rule.Flags & fwpmFilterFlagsPersistent) != 0,
			BootTime:     (rule.Flags & fwpmFilterFlagsBootTime) != 0,
			Provider:     rule.ProviderKey,
			ProviderData: fromByteBlob(&rule.ProviderData),
			Disabled:     (rule.Flags & fwpmFilterFlagsDisabled) != 0,
		}
		if rule.EffectiveWeight.Type == dataTypeUint64 {
			r.Weight = **(**uint64)(unsafe.Pointer(&rule.EffectiveWeight.Value))
		}
		if r.Action == ActionCalloutTerminating || r.Action == ActionCalloutInspection || r.Action == ActionCalloutUnknown {
			r.Callout = rule.Action.GUID
		}
		if r.Action == ActionCalloutTerminating || r.Action == ActionCalloutUnknown {
			r.PermitIfMissing = (rule.Flags & fwpmFilterFlagsPermitIfCalloutUnregistered) != 0
		}

		ft := layerTypes[r.Layer]
		if ft == nil {
			return nil, fmt.Errorf("unknown layer %s", r.Layer)
		}

		ms, err := fromCondition0(rule.FilterConditions, rule.NumFilterConditions, ft)
		if err != nil {
			return nil, err
		}

		r.Conditions = ms

		ret = append(ret, r)
	}

	return ret, nil
}

func fromCondition0(condArray *fwpmFilterCondition0, num uint32, fieldTypes fieldTypes) ([]*Match, error) {
	var conditions []fwpmFilterCondition0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&conditions))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(condArray))

	var ret []*Match

	for i := range conditions {
		cond := &conditions[i]
		fieldType, ok := fieldTypes[cond.FieldKey]
		if !ok {
			return nil, fmt.Errorf("unknown field %s", cond.FieldKey)
		}

		v, err := fromValue0((*fwpValue0)(unsafe.Pointer(&cond.Value)), fieldType)
		if err != nil {
			return nil, fmt.Errorf("getting value for match [%s %s]: %w", GUIDName(cond.FieldKey), cond.MatchType, err)
		}
		m := &Match{
			Key:   cond.FieldKey,
			Op:    cond.MatchType,
			Value: v,
		}

		ret = append(ret, m)
	}

	return ret, nil
}

// fromValue converts a fwpValue0 to the corresponding Go value.
func fromValue0(v *fwpValue0, ftype reflect.Type) (interface{}, error) {
	// For most types, the field type and raw data type match up. But
	// for some, the raw type can vary from the field type
	// (e.g. comparing an IP to a prefix). Get the complex matchups
	// out of the way first.
	mapErr := func() error {
		return fmt.Errorf("can't map condition type %s into type %s", v.Type, ftype)
	}
	if fieldTypeMap[v.Type] != ftype {
		switch {
		case ftype == reflect.TypeOf(netaddr.IP{}) && v.Type != dataTypeRange:
			switch v.Type {
			case dataTypeUint32:
				u32 := *(*uint32)(unsafe.Pointer(&v.Value))
				return ipv4From32(u32), nil
			case dataTypeByteArray16:
				var bs [16]byte
				copy(bs[:], fromBytes(v.Value, 16))
				return netaddr.IPFrom16(bs), nil
			case dataTypeV4AddrMask:
				return parseV4AddrAndMask(&v.Value), nil
			case dataTypeV6AddrMask:
				return parseV6AddrAndMask(&v.Value), nil
			default:
				return nil, mapErr()
			}
		case v.Type == dataTypeSecurityDescriptor:
			if ftype != reflect.TypeOf(TokenInformation{}) && ftype != reflect.TypeOf(TokenAccessInformation(nil)) {
				return nil, mapErr()
			}
			return parseSecurityDescriptor(&v.Value)
		case v.Type == dataTypeSID:
			if ftype != reflect.TypeOf(TokenInformation{}) && ftype != reflect.TypeOf(TokenAccessInformation(nil)) {
				return nil, mapErr()
			}
			return parseSID(&v.Value)
		case v.Type == dataTypeRange:
			return parseRange0(&v.Value, ftype)
		default:
			return nil, mapErr()
		}
	}

	// That's all the complicated ones. For everything else we can
	// parse by looking only at the raw type.
	//
	// Note that, depending on the type, we take either the
	// unsafe.Pointer of v.Value, or &v.Value. The extra & is for
	// values that get inlined into the Value field, everything else
	// is when Value is a pointer to the actual value.
	//
	// See [TODO docs of FWP_VALUE0 here] for details.

	switch v.Type {
	case dataTypeUint8:
		return *(*uint8)(unsafe.Pointer(&v.Value)), nil
	case dataTypeUint16:
		return *(*uint16)(unsafe.Pointer(&v.Value)), nil
	case dataTypeUint32:
		return *(*uint32)(unsafe.Pointer(&v.Value)), nil
	case dataTypeUint64:
		return **(**uint64)(unsafe.Pointer(&v.Value)), nil
	case dataTypeByteArray16:
		var ret [16]byte
		copy(ret[:], fromBytes(v.Value, 16))
		return ret, nil
	case dataTypeByteBlob:
		return fromByteBlob(*(**fwpByteBlob)(unsafe.Pointer(&v.Value))), nil
	case dataTypeSID:
		return parseSID(&v.Value)
	// case dataTypeSecurityDescriptor:
	// 	return parseSecurityDescriptor(v.Value)
	case dataTypeTokenInformation:
		return nil, errors.New("TODO TokenInformation")
	case dataTypeTokenAccessInformation:
		return nil, errors.New("TODO TokenAccessInformation")
	case dataTypeArray6:
		var ret [6]byte
		copy(ret[:], fromBytes(v.Value, 6))
		return ret, nil
	case dataTypeBitmapIndex:
		return nil, errors.New("TODO BitmapIndex")
	case dataTypeV4AddrMask:
		return parseV4AddrAndMask(&v.Value), nil
	case dataTypeV6AddrMask:
		return parseV6AddrAndMask(&v.Value), nil
	default:
		return nil, fmt.Errorf("unknown value type %d", v.Type)
	}
}

func parseV4AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v4 := *(**fwpV4AddrAndMask)(unsafe.Pointer(v))
	ip := netaddr.IPv4(uint8(v4.Addr>>24), uint8(v4.Addr>>16), uint8(v4.Addr>>8), uint8(v4.Addr))
	bits := uint8(32 - bits.TrailingZeros32(v4.Mask))
	return netaddr.IPPrefix{
		IP:   ip,
		Bits: bits,
	}
}

func parseV6AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v6 := *(**fwpV6AddrAndMask)(unsafe.Pointer(v))
	return netaddr.IPPrefix{
		IP:   netaddr.IPFrom16(v6.Addr),
		Bits: v6.PrefixLength,
	}
}

func parseSID(v *uintptr) (*windows.SID, error) {
	// TODO: export IsValidSid in x/sys/windows so we can vaguely
	// verify this pointer.
	sid := *(**windows.SID)(unsafe.Pointer(v))
	// Copy the SID into Go memory.
	dsid, err := sid.Copy()
	if err != nil {
		return nil, err
	}
	return dsid, nil
}

func parseSecurityDescriptor(v *uintptr) (*windows.SECURITY_DESCRIPTOR, error) {
	// The security descriptor is embedded in the API response as
	// a byte slice.
	bb := fromByteBlob(*(**fwpByteBlob)(unsafe.Pointer(v)))
	relSD := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&bb[0]))
	return relSD, nil
}

func parseRange0(v *uintptr, ftype reflect.Type) (interface{}, error) {
	r := *(**fwpRange0)(unsafe.Pointer(v))
	from, err := fromValue0(&r.From, ftype)
	if err != nil {
		return nil, err
	}
	to, err := fromValue0(&r.To, ftype)
	if err != nil {
		return nil, err
	}
	if reflect.TypeOf(from) != reflect.TypeOf(to) {
		return nil, fmt.Errorf("range.From and range.To types don't match: %s / %s", reflect.TypeOf(from), reflect.TypeOf(to))
	}
	if reflect.TypeOf(from) == reflect.TypeOf(netaddr.IP{}) {
		// TODO: only return IPRange, not IPRange or IPPrefix?
		// Less work to parse on the receiving end.
		ret := netaddr.IPRange{
			From: from.(netaddr.IP),
			To:   to.(netaddr.IP),
		}
		if pfx, ok := ret.Prefix(); ok {
			return pfx, nil
		}
		return ret, nil
	}
	return Range{from, to}, nil
}

func ipv4From32(v uint32) netaddr.IP {
	return netaddr.IPv4(uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v))
}

func fromBytes(bb uintptr, length int) []byte {
	var bs []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Cap = length
	sh.Len = length
	sh.Data = bb
	return append([]byte(nil), bs...)
}

// fromByteBlob extracts the bytes from bb and returns them as a
// []byte that doesn't alias C memory.
func fromByteBlob(bb *fwpByteBlob) []byte {
	if bb == nil || bb.Size == 0 {
		return nil
	}

	var blob []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size)
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))

	return append([]byte(nil), blob...)
}
