package winfirewall

import (
	"math/bits"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
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
