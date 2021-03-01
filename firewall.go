package wf

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

// Session is a connection to the WFP API.
type Session struct {
	handle windows.Handle
}

// SessionOptions configure a Session.
type SessionOptions struct {
	// Name is a short name for the session, shown in Windows
	// administrative tools.
	Name string
	// Description is a short description for the session, shown in
	// Windows administrative tools.
	Description string
	// Dynamic, if true, indicates that all objects created during the
	// session should be removed when the session is closed or the
	// session-owning process terminates. Dynamic sessions are meant
	// for adding firewall configuration that should not outlast your
	// program's execution.
	Dynamic bool
	// TransactionStartTimeout is how long the session is willing to
	// wait to acquire the global transaction lock. If zero, WFP's
	// default timeout (15 seconds) is used.
	TransactionStartTimeout time.Duration
}

// New connects to the WFP API.
func New(opts *SessionOptions) (*Session, error) {
	if opts == nil {
		opts = &SessionOptions{}
	}

	session := fwpmSession0{
		DisplayData: fwpmDisplayData0{
			Name:        windows.StringToUTF16Ptr(opts.Name),
			Description: windows.StringToUTF16Ptr(opts.Description),
		},
		TxnWaitTimeoutMillis: uint32(opts.TransactionStartTimeout.Milliseconds()),
	}
	if opts.Dynamic {
		session.Flags = fwpmSession0FlagDynamic
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

// Close implements io.Closer.
func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	return fwpmEngineClose0(s.handle)
}

// Layer is a point in the packet processing path where filter rules
// can be applied.
type Layer struct {
	// Key is the unique identifier for this layer.
	Key windows.GUID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the layer's function.
	Description string
	// InKernel reports whether this layer's filtering is done in
	// kernel mode.
	InKernel bool
	// ClassifyMostly reports whether this layer is optimized for
	// packet classification at the expense of enumeration
	// performance.
	ClassifyMostly bool
	// Buffered reports whether this layer is buffered (unknown what
	// that actually means).
	Buffered bool
	// DefaultSublayerKey is the unique identifier for the default
	// sublayer into which filter rules are added.
	DefaultSublayerKey windows.GUID
	// Fields describes the fields that are available in this layer to
	// be matched against.
	Fields []*Field
}

// Field is a piece of information that a layer makes available to
// filter rules for matching.
type Field struct {
	// Key is the unique identifier for the field.
	Key windows.GUID
	// Type is the type of the field.
	Type reflect.Type
}

// TokenAccessInformation is a temporary type representing a Windows
// TOKEN_ACCESS_INFORMATION struct.
//
// TODO: expose in x/sys/windows, https://github.com/inetaf/wf/issues/1
type TokenAccessInformation []byte

// Bitmap64 is a 64-bit wide bit map.
type Bitmap64 uint64

// BitmapIndex is an index into a Bitmap64.
type BitmapIndex uint8 // TODO: this is a guess, the API doesn't document what the underlying type is.

// TokenInformation defines a set of security identifiers.
// For more information see https://docs.microsoft.com/en-us/windows/win32/api/Fwptypes/ns-fwptypes-fwp_token_information.
type TokenInformation struct {
	SIDS           []windows.SIDAndAttributes
	RestrictedSIDs []windows.SIDAndAttributes
}

// fieldTypeMap maps DataType to a Go value of that type.
var fieldTypeMap = map[DataType]interface{}{
	DataTypeUint8:                  uint8(0),
	DataTypeUint16:                 uint16(0),
	DataTypeUint32:                 uint32(0),
	DataTypeUint64:                 uint64(0),
	DataTypeInt8:                   int8(0),
	DataTypeInt16:                  int16(0),
	DataTypeInt32:                  int32(0),
	DataTypeInt64:                  int64(0),
	DataTypeFloat:                  float32(0),
	DataTypeDouble:                 float64(0),
	DataTypeByteArray16:            [16]byte{},
	DataTypeByteBlob:               []byte(nil),
	DataTypeSID:                    windows.SID{},
	DataTypeSecurityDescriptor:     windows.SECURITY_DESCRIPTOR{},
	DataTypeTokenInformation:       TokenInformation{},
	DataTypeTokenAccessInformation: TokenAccessInformation(nil),
	DataTypeUnicodeString:          "",
	DataTypeArray6:                 [6]byte{},
	DataTypeBitmapIndex:            BitmapIndex(0),
	DataTypeBitmapArray64:          BitmapArray64(0),
	DataTypeV4AddrMask:             netaddr.IPPrefix{},
	DataTypeV6AddrMask:             netaddr.IPPrefix{},

	// TODO: not sure how to represent yet. It's only used when
	// defining filters, layers don't provide ranges to filters.
	// DataTypeRange
}

// fieldType returns the reflect.Type for a field, or an error if the
// field has an unknown or infeasible type.
func fieldType(f fwpmField0) (reflect.Type, error) {
	// IP addresses are represented as either a uint32 or a 16-byte
	// array, with a modifier flag indicating that it's an IP
	// address. Use plain IPs when exposing in Go.
	if f.Type == fwpmFieldTypeIPAddress {
		if f.DataType != DataTypeUint32 && f.DataType != DataTypeByteArray16 {
			return nil, fmt.Errorf("field has IP address type, but underlying datatype is %s (want Uint32 or ByteArray16)", f.DataType)
		}
		return reflect.TypeOf(netaddr.IP{}), nil
	}
	// Flags are a uint32 with a modifier. This just checks that there
	// are no surprise flag fields of other types.
	if f.Type == fwpmFieldTypeFlags {
		if f.DataType != DataTypeUint32 {
			return nil, fmt.Errorf("field has flag type, but underlying datatype is %s (want Uint32)", f.DataType)
		}
		return reflect.TypeOf(uint32(0)), nil
	}

	if v, ok := fieldTypeMap[f.DataType]; ok {
		return reflect.TypeOf(v), nil
	}

	return nil, fmt.Errorf("unknown data type %s", f.DataType)
}

// Layers returns information on available WFP layers.
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

		layers, err := toLayers(layersArray, num)
		if err != nil {
			return nil, err
		}
		ret = append(ret, layers...)

		if num < pageSize {
			return ret, nil
		}
	}
}

// toLayers converts a C array of fwpmLayer0 to a safe-to-use Layer
// slice.
func toLayers(layersArray **fwpmLayer0, numLayers uint32) ([]*Layer, error) {
	defer fwpmFreeMemory0(uintptr(unsafe.Pointer(&layersArray)))

	var ret []*Layer

	var layers []*fwpmLayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
	sh.Cap = int(numLayers)
	sh.Len = int(numLayers)
	sh.Data = uintptr(unsafe.Pointer(layersArray))

	for _, layer := range layers {
		var fields []fwpmField0
		sh = (*reflect.SliceHeader)(unsafe.Pointer(&fields))
		sh.Cap = int(layer.NumFields)
		sh.Len = int(layer.NumFields)
		sh.Data = uintptr(unsafe.Pointer(layer.Fields))

		l := &Layer{
			Key:         layer.LayerKey,
			Name:        windows.UTF16PtrToString(layer.DisplayData.Name),
			Description: windows.UTF16PtrToString(layer.DisplayData.Description),
			// Note: we don't expose the "builtin" flag, because
			// as of Windows 10, all layers are built-in and there
			// is no way to add more layers.
			InKernel:           (layer.Flags & fwpmLayerFlagsKernel) != 0,
			ClassifyMostly:     (layer.Flags & fwpmLayerFlagsClassifyMostly) != 0,
			Buffered:           (layer.Flags & fwpmLayerFlagsBuffered) != 0,
			DefaultSublayerKey: layer.DefaultSublayerKey,
		}
		for _, field := range fields {
			typ, err := fieldType(field)
			if err != nil {
				return nil, fmt.Errorf("finding type of field %s: %w", GUIDName(field.Key), err)
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

// GUIDName returns a human-readable name for standard WFP GUIDs. If g
// is not a standard WFP GUID, g.String() is returned.
func GUIDName(g windows.GUID) string {
	if n := guidNames[g]; n != "" {
		return n
	}
	return g.String()
}
