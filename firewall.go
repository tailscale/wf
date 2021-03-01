package wf

import (
	"errors"
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

// fieldTypeMap maps dataType to a Go value of that type.
var fieldTypeMap = map[dataType]interface{}{
	dataTypeUint8:                  uint8(0),
	dataTypeUint16:                 uint16(0),
	dataTypeUint32:                 uint32(0),
	dataTypeUint64:                 uint64(0),
	dataTypeInt8:                   int8(0),
	dataTypeInt16:                  int16(0),
	dataTypeInt32:                  int32(0),
	dataTypeInt64:                  int64(0),
	dataTypeFloat:                  float32(0),
	dataTypeDouble:                 float64(0),
	dataTypeByteArray16:            [16]byte{},
	dataTypeByteBlob:               []byte(nil),
	dataTypeSID:                    windows.SID{},
	dataTypeSecurityDescriptor:     windows.SECURITY_DESCRIPTOR{},
	dataTypeTokenInformation:       TokenInformation{},
	dataTypeTokenAccessInformation: TokenAccessInformation(nil),
	dataTypeUnicodeString:          "",
	dataTypeArray6:                 [6]byte{},
	dataTypeBitmapIndex:            BitmapIndex(0),
	dataTypeBitmapArray64:          Bitmap64(0),
	dataTypeV4AddrMask:             netaddr.IPPrefix{},
	dataTypeV6AddrMask:             netaddr.IPPrefix{},

	// TODO: not sure how to represent yet. It's only used when
	// defining filters, layers don't provide ranges to filters.
	// dataTypeRange
}

// fieldType returns the reflect.Type for a field, or an error if the
// field has an unknown or infeasible type.
func fieldType(f fwpmField0) (reflect.Type, error) {
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

// A Sublayer is a container for filtering rules.
type Sublayer struct {
	// Key is the unique identifier for this sublayer.
	Key windows.GUID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the Sublayer.
	Description string
	// Persistent indicates whether the sublayer is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// Provider optionally identifies the Provider that manages this
	// sublayer.
	Provider *windows.GUID
	// ProviderData is optional opaque data that can be held on behalf
	// of the Provider.
	ProviderData []byte
	// Weight specifies the priority of this sublayer relative to
	// other sublayers. Higher-weighted sublayers are invoked first.
	Weight uint16
}

// Sublayers returns available Sublayers. If provider is non-nil, only
// Sublayers registered to that Provider are returned.
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

		ret = append(ret, toSublayers(sublayersArray, num)...)

		if num < pageSize {
			return ret, nil
		}
	}
}

// toSublayers converts a C array of fwpmSublayer0 to a safe-to-use Sublayer
// slice.
func toSublayers(sublayersArray **fwpmSublayer0, numSublayers uint32) []*Sublayer {
	defer fwpmFreeMemory0(uintptr(unsafe.Pointer(&sublayersArray)))

	var ret []*Sublayer

	var sublayers []*fwpmSublayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sublayers))
	sh.Cap = int(numSublayers)
	sh.Len = int(numSublayers)
	sh.Data = uintptr(unsafe.Pointer(sublayersArray))

	for _, sublayer := range sublayers {
		s := &Sublayer{
			Key:          sublayer.SublayerKey,
			Name:         windows.UTF16PtrToString(sublayer.DisplayData.Name),
			Description:  windows.UTF16PtrToString(sublayer.DisplayData.Description),
			Persistent:   (sublayer.Flags & fwpmSublayerFlagsPersistent) != 0,
			ProviderData: fromByteBlob(sublayer.ProviderData),
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

// AddSublayer creates a new Sublayer.
func (s *Session) AddSublayer(sl *Sublayer) error {
	// the WFP API accepts zero GUIDs and interprets it as "give me a
	// random GUID". However, we can't get that GUID back out, so it
	// would be pointless to make such a request. Stop it here.
	if sl.Key == (windows.GUID{}) {
		return errors.New("Sublayer.Key cannot be zero")
	}

	sl0 := fwpmSublayer0{
		SublayerKey:  sl.Key,
		DisplayData:  toDisplayData(sl.Name, sl.Description),
		ProviderKey:  sl.Provider,
		ProviderData: toByteBlob(sl.ProviderData),
		Weight:       sl.Weight,
	}

	return fwpmSubLayerAdd0(s.handle, &sl0, nil) // TODO: security descriptor
}

// DeleteSublayer deletes the Sublayer whose GUID is id.
func (s *Session) DeleteSublayer(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmSubLayerDeleteByKey0(s.handle, &id)
}

// A Provider is an entity that owns sublayers and filtering rules.
type Provider struct {
	// Key is the unique identifier for this provider.
	Key windows.GUID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the provider.
	Description string
	// Persistent indicates whether the provider is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// Data is optional opaque data that can be held on behalf of the
	// Provider.
	Data []byte
	// ServiceName is an optional Windows service name. If present,
	// the rules owned by this Provider are only activated when the
	// service is active.
	ServiceName string

	// Disabled indicates whether the rules owned by this Provider are
	// disabled due to its associated service being
	// disabled. Read-only, ignored on Provider creation.
	Disabled bool
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

		ret = append(ret, toProviders(providersArray, num)...)

		if num < pageSize {
			return ret, nil
		}
	}
}

// toProviders converts a C array of fwpmProvider0 to a safe-to-use Provider
// slice.
func toProviders(providersArray **fwpmProvider0, numProviders uint32) []*Provider {
	defer fwpmFreeMemory0(uintptr(unsafe.Pointer(&providersArray)))

	var ret []*Provider

	var providers []*fwpmProvider0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&providers))
	sh.Cap = int(numProviders)
	sh.Len = int(numProviders)
	sh.Data = uintptr(unsafe.Pointer(providersArray))

	for _, provider := range providers {
		p := &Provider{
			Key:         provider.ProviderKey,
			Name:        windows.UTF16PtrToString(provider.DisplayData.Name),
			Description: windows.UTF16PtrToString(provider.DisplayData.Description),
			Persistent:  (provider.Flags & fwpmProviderFlagsPersistent) != 0,
			Disabled:    (provider.Flags & fwpmProviderFlagsDisabled) != 0,
			Data:        fromByteBlob(provider.ProviderData),
			ServiceName: windows.UTF16PtrToString(provider.ServiceName),
		}
		ret = append(ret, p)
	}

	return ret
}

// AddProvider creates a new provider.
func (s *Session) AddProvider(p *Provider) error {
	if p.Key == (windows.GUID{}) {
		return errors.New("Provider.Key cannot be zero")
	}

	p0 := &fwpmProvider0{
		ProviderKey:  p.Key,
		DisplayData:  toDisplayData(p.Name, p.Description),
		ProviderData: toByteBlob(p.Data),
		ServiceName:  windows.StringToUTF16Ptr(p.ServiceName),
	}
	if p.Persistent {
		p0.Flags = fwpmProviderFlagsPersistent
	}

	return fwpmProviderAdd0(s.handle, p0, nil)
}

// DeleteProvider deletes the Provider whose GUID is id. A provider
// can only be deleted once all the resources it owns have been
// deleted.
func (s *Session) DeleteProvider(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmProviderDeleteByKey0(s.handle, &id)
}

// GUIDName returns a human-readable name for standard WFP GUIDs. If g
// is not a standard WFP GUID, g.String() is returned.
func GUIDName(g windows.GUID) string {
	if n := guidNames[g]; n != "" {
		return n
	}
	return g.String()
}

// fromByteBlob extracts the bytes from bb and returns them as a
// []byte that doesn't alias C memory.
func fromByteBlob(bb fwpByteBlob) []byte {
	if bb.Size == 0 {
		return nil
	}

	var blob []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size)
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))

	return append([]byte(nil), blob...)
}

// toByteBlob packs bs into fwpByteBlob. The returned fwpByteBlob
// shares memory with bs.
func toByteBlob(bs []byte) fwpByteBlob {
	if len(bs) == 0 {
		return fwpByteBlob{0, nil}
	}
	return fwpByteBlob{
		Size: uint32(len(bs)),
		Data: &bs[0],
	}
}

// toDisplayData packs name and description into a fwpmDisplayData0.
func toDisplayData(name, description string) fwpmDisplayData0 {
	return fwpmDisplayData0{
		Name:        windows.StringToUTF16Ptr(name),
		Description: windows.StringToUTF16Ptr(description),
	}
}
