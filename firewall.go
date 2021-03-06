package wf

import (
	"errors"
	"fmt"
	"math/bits"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
	"inet.af/netaddr"
)

type fieldTypes map[windows.GUID]reflect.Type
type layerTypes map[windows.GUID]fieldTypes

// Session is a connection to the WFP API.
type Session struct {
	handle windows.Handle
	// layerTypes is a map of layer ID -> field ID -> Go type for that field.
	layerTypes layerTypes
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

	ret := &Session{
		handle:     handle,
		layerTypes: layerTypes{},
	}

	// Populate the layer type cache.
	layers, err := ret.Layers()
	if err != nil {
		ret.Close()
		return nil, err
	}
	for _, layer := range layers {
		fields := fieldTypes{}
		for _, field := range layer.Fields {
			fields[field.Key] = field.Type
		}
		ret.layerTypes[layer.Key] = fields
	}

	return ret, nil
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

// BitmapIndex is an index into a Bitmap64.
type BitmapIndex uint8 // TODO: this is a guess, the API doesn't document what the underlying type is.

type Range struct {
	From, To interface{}
}

// TokenInformation defines a set of security identifiers.
// For more information see https://docs.microsoft.com/en-us/windows/win32/api/Fwptypes/ns-fwptypes-fwp_token_information.
type TokenInformation struct {
	SIDS           []windows.SIDAndAttributes
	RestrictedSIDs []windows.SIDAndAttributes
}

// fieldTypeMap maps dataType to a Go value of that type.
var fieldTypeMap = map[dataType]reflect.Type{
	dataTypeUint8:                  reflect.TypeOf(uint8(0)),
	dataTypeUint16:                 reflect.TypeOf(uint16(0)),
	dataTypeUint32:                 reflect.TypeOf(uint32(0)),
	dataTypeUint64:                 reflect.TypeOf(uint64(0)),
	dataTypeByteArray16:            reflect.TypeOf([16]byte{}),
	dataTypeByteBlob:               reflect.TypeOf([]byte(nil)),
	dataTypeSID:                    reflect.TypeOf(&windows.SID{}),
	dataTypeSecurityDescriptor:     reflect.TypeOf(&windows.SECURITY_DESCRIPTOR{}),
	dataTypeTokenInformation:       reflect.TypeOf(TokenInformation{}),
	dataTypeTokenAccessInformation: reflect.TypeOf(TokenAccessInformation(nil)),
	dataTypeArray6:                 reflect.TypeOf([6]byte{}),
	dataTypeBitmapIndex:            reflect.TypeOf(BitmapIndex(0)),
	dataTypeV4AddrMask:             reflect.TypeOf(netaddr.IPPrefix{}),
	dataTypeV6AddrMask:             reflect.TypeOf(netaddr.IPPrefix{}),
	dataTypeRange:                  reflect.TypeOf(Range{}),
}

var fieldTypeMapReverse = map[reflect.Type]dataType{}

func init() {
	for dt, rt := range fieldTypeMap {
		fieldTypeMapReverse[rt] = dt
	}
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

	if t, ok := fieldTypeMap[f.DataType]; ok {
		return t, nil
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

// MatchType is the operator to use when testing a field in a Match.
type MatchType uint32 // do not change type, used in C calls

const (
	MatchTypeEqual MatchType = iota
	MatchTypeGreater
	MatchTypeLess
	MatchTypeGreaterOrEqual
	MatchTypeLessOrEqual
	MatchTypeRange // true if the field value is within the Range.
	MatchTypeFlagsAllSet
	MatchTypeFlagsAnySet
	MatchTypeFlagsNoneSet
	MatchTypeEqualCaseInsensitive // only valid on strings, no string fields exist
	MatchTypeNotEqual
	MatchTypePrefix    // TODO: not well documented. Is this prefix.Contains(ip) ?
	MatchTypeNotPrefix // TODO: see above.
)

var mtStr = map[MatchType]string{
	MatchTypeEqual:                "==",
	MatchTypeGreater:              ">",
	MatchTypeLess:                 "<",
	MatchTypeGreaterOrEqual:       ">=",
	MatchTypeLessOrEqual:          "<=",
	MatchTypeRange:                "in",
	MatchTypeFlagsAllSet:          "F[all]",
	MatchTypeFlagsAnySet:          "F[any]",
	MatchTypeFlagsNoneSet:         "F[none]",
	MatchTypeEqualCaseInsensitive: "i==",
	MatchTypeNotEqual:             "!=",
	MatchTypePrefix:               "pfx",
	MatchTypeNotPrefix:            "!pfx",
}

func (m MatchType) String() string {
	return mtStr[m]
}

// Match is a matching test that gets run against a layer's field.
type Match struct {
	Key   windows.GUID
	Op    MatchType
	Value interface{}
}

func (m Match) String() string {
	val := m.Value
	if m.Key == guidConditionALEAppID {
		d := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		bs, err := d.Bytes(m.Value.([]byte))
		if err != nil {
			panic(err)
		}
		val = string(bs[:len(bs)-1])
	}
	return fmt.Sprintf("%s %s %v (%T)", GUIDName(m.Key), m.Op, val, m.Value)
}

// Action is an action the filtering engine can execute.
type Action uint32

const (
	// ActionBlock blocks a packet or session.
	ActionBlock Action = 0x1001
	// ActionPermit permits a packet or session.
	ActionPermit Action = 0x1002
	// ActionCalloutTerminating invokes a callout that must return a
	// permit or block verdict.
	ActionCalloutTerminating Action = 0x5003
	// ActionCalloutInspection invokes a callout that is expected to
	// not return a verdict (i.e. a read-only callout).
	ActionCalloutInspection Action = 0x6004
	// ActionCalloutUnknown invokes a callout that may return a permit
	// or block verdict.
	ActionCalloutUnknown Action = 0x4005
)

// A Rule is an action to take on packets that match a set of
// conditions.
type Rule struct {
	// Key is the unique identifier for this rule.
	Key windows.GUID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the rule.
	Description string
	// Layer is the ID of the layer in which the rule runs.
	Layer windows.GUID
	// Sublayer is the ID of the sublayer in which the rule runs.
	Sublayer windows.GUID
	// Weight is the priority of the rule relative to other rules in
	// its sublayer.
	Weight uint64
	// Conditions are the tests which must pass for this rule to apply
	// to a packet.
	Conditions []*Match
	// Action is the action to take on matching packets.
	Action Action
	// Callout is the ID of the callout to invoke. Only valid if
	// Action is ActionCalloutTerminating, ActionCalloutInspection, or
	// ActionCalloutUnknown.
	Callout windows.GUID
	// PermitIfMissing, if set, indicates that a callout action to a
	// callout ID that isn't registered should be translated into an
	// ActionPermit, rather than an ActionBlock. Only relevant if
	// Action is ActionCalloutTerminating or ActionCalloutUnknown.
	PermitIfMissing bool

	// Persistent indicates whether the rule is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// BootTime indicates that this rule applies only during early
	// boot, before the filtering engine fully starts and hands off to
	// the normal runtime rules.
	BootTime bool

	// Provider optionally identifies the Provider that manages this
	// rule.
	Provider *windows.GUID
	// ProviderData is optional opaque data that can be held on behalf
	// of the Provider.
	ProviderData []byte

	// Disabled indicates whether the rule is currently disabled due
	// to its provider being associated with an inactive Windows
	// service. See Provider.ServiceName for details.
	Disabled bool
}

// TODO: figure out what currently unexposed flags do: ClearActionRight, Indexed
// TODO: figure out what ProviderContextKey is about. MSDN doesn't explain what contexts are.

func (s *Session) Rules() ([]*Rule, error) { // TODO: support filter settings
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*Rule

	const pageSize = 100
	for {
		var rulesArray **fwpmFilter0
		var num uint32
		if err := fwpmFilterEnum0(s.handle, enum, pageSize, &rulesArray, &num); err != nil {
			return nil, err
		}

		rules, err := toRules(rulesArray, num, s.layerTypes)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rules...)

		if num < pageSize {
			return ret, nil
		}
	}
}

func (s *Session) AddRule(r *Rule) error {
	f, ref, err := toFilter0(r, s.layerTypes)
	if err != nil {
		return err
	}

	if err := fwpmFilterAdd0(s.handle, f, nil, nil); err != nil {
		return err
	}

	runtime.KeepAlive(ref)

	return nil
}

func toFilter0(r *Rule, lt layerTypes) (*fwpmFilter0, interface{}, error) {
	conds, ref, err := toConditions(r.Conditions, lt[r.Layer])
	if err != nil {
		return nil, nil, err
	}

	ret := &fwpmFilter0{
		FilterKey:    r.Key,
		DisplayData:  toDisplayData(r.Name, r.Description),
		ProviderKey:  r.Provider,
		ProviderData: toByteBlob(r.ProviderData),
		LayerKey:     r.Layer,
		SublayerKey:  r.Sublayer,
		Weight: fwpValue0{
			Type:  dataTypeUint64,
			Value: (*uintptr)(unsafe.Pointer(&r.Weight)),
		},
		NumFilterConditions: uint32(len(conds)), // TODO: overflow?
		FilterConditions:    &conds[0],
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

	return ret, ref, nil
}

func toConditions(ms []*Match, ft fieldTypes) ([]fwpmFilterCondition0, interface{}, error) {
	ret := make([]fwpmFilterCondition0, 0, len(ms))
	refs := make([]interface{}, 0, len(ms))
	for _, m := range ms {
		v, ref, err := toValue(m.Value, ft[m.Key])
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, fwpmFilterCondition0{
			FieldKey:  m.Key,
			MatchType: m.Op,
			Value:     v,
		})
		refs = append(refs, ref)
	}

	return ret, refs, nil
}

func toValue(v interface{}, ftype reflect.Type) (ret fwpConditionValue0, reference interface{}, err error) {
	mapErr := func() error {
		return fmt.Errorf("can't map type %T into condition type %v", v, ftype)
	}

	ret.Type = fieldTypeMapReverse[ftype]
	switch ret.Type {
	case dataTypeUint8:
		u, ok := v.(uint8)
		if !ok {
			return ret, nil, mapErr()
		}
		*(*uint8)(unsafe.Pointer(&ret.Value)) = u
	case dataTypeUint16:
		u, ok := v.(uint16)
		if !ok {
			return ret, nil, mapErr()
		}
		*(*uint16)(unsafe.Pointer(&ret.Value)) = u
	case dataTypeUint32:
		u, ok := v.(uint32)
		if !ok {
			return ret, nil, mapErr()
		}
		*(*uint32)(unsafe.Pointer(&ret.Value)) = u
	case dataTypeUint64:
		u, ok := v.(uint64)
		if !ok {
			return ret, nil, mapErr()
		}
		pu := &u
		reference = pu
		ret.Value = (*uintptr)(unsafe.Pointer(pu))
	case dataTypeByteBlob:
		u, ok := v.([]byte)
		if !ok {
			return ret, nil, mapErr()
		}
		bb := toByteBlob(u)
		ret.Value = (*uintptr)(unsafe.Pointer(&bb))
	case dataTypeSID:
		u, ok := v.(*windows.SID)
		if !ok {
			return ret, nil, mapErr()
		}
		ret.Value = (*uintptr)(unsafe.Pointer(u))
	}

	// TODO: bitmapIndex
	// TODO: dataTypeArray16
	// TODO: dataTypeArray6
	// TODO: dataTypeSecurityDescriptor
	// TODO: dataTypeTokenInformation
	// TODO: dataTypeTokenAccessInformation
	// TODO: addr masks

	return ret, reference, nil
}

func toRules(rulesArray **fwpmFilter0, num uint32, layerTypes layerTypes) ([]*Rule, error) {
	defer fwpmFreeMemory0(uintptr(unsafe.Pointer(&rulesArray)))

	var rules []*fwpmFilter0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&rules))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(rulesArray))

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
			ProviderData: fromByteBlob(rule.ProviderData),
			Disabled:     (rule.Flags & fwpmFilterFlagsDisabled) != 0,
		}
		if rule.EffectiveWeight.Type == dataTypeUint64 {
			r.Weight = *(*uint64)(unsafe.Pointer(rule.EffectiveWeight.Value))
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

		ms, err := fromConditions(rule.FilterConditions, rule.NumFilterConditions, ft)
		if err != nil {
			return nil, err
		}

		r.Conditions = ms

		ret = append(ret, r)
	}

	return ret, nil
}

func fromConditions(condArray *fwpmFilterCondition0, num uint32, fieldTypes fieldTypes) ([]*Match, error) {
	var conditions []fwpmFilterCondition0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&conditions))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(condArray))

	var ret []*Match

	for _, cond := range conditions {
		fieldType, ok := fieldTypes[cond.FieldKey]
		if !ok {
			return nil, fmt.Errorf("unknown field %s", cond.FieldKey)
		}

		v, err := fromValue(fwpValue0(cond.Value), fieldType)
		if err != nil {
			return nil, fmt.Errorf("getting value for match [%s %s]: %w", GUIDName(cond.FieldKey), cond.MatchType, err)
		}
		m := &Match{
			Key:   cond.FieldKey,
			Op:    cond.MatchType,
			Value: v,
		}
		// TODO: check if the match makes sense?

		ret = append(ret, m)
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

// fromValue converts a fwpValue0 to the corresponding Go value.
func fromValue(v fwpValue0, ftype reflect.Type) (interface{}, error) {
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
				return parseV4AddrAndMask(v.Value), nil
			case dataTypeV6AddrMask:
				return parseV6AddrAndMask(v.Value), nil
			default:
				return nil, mapErr()
			}
		case v.Type == dataTypeSecurityDescriptor:
			if ftype != reflect.TypeOf(TokenInformation{}) && ftype != reflect.TypeOf(TokenAccessInformation(nil)) {
				return nil, mapErr()
			}
			return parseSecurityDescriptor(v.Value)
		case v.Type == dataTypeSID:
			if ftype != reflect.TypeOf(TokenInformation{}) && ftype != reflect.TypeOf(TokenAccessInformation(nil)) {
				return nil, mapErr()
			}
			return parseSID(v.Value)
		case v.Type == dataTypeRange:
			r := (*fwpRange0)(unsafe.Pointer(v.Value))
			from, err := fromValue(r.From, ftype)
			if err != nil {
				return nil, fmt.Errorf("getting range.From: %w", err)
			}
			to, err := fromValue(r.To, ftype)
			if err != nil {
				return nil, fmt.Errorf("getting range.To: %w", err)
			}
			if reflect.TypeOf(from) != reflect.TypeOf(to) {
				panic(fmt.Sprintf("range.From and range.To types don't match: %s / %s", reflect.TypeOf(from), reflect.TypeOf(to)))
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
		return *(*uint64)(unsafe.Pointer(v.Value)), nil
	case dataTypeByteArray16:
		var ret [16]byte
		copy(ret[:], fromBytes(v.Value, 16))
		return ret, nil
	case dataTypeByteBlob:
		return fromByteBlob(*(*fwpByteBlob)(unsafe.Pointer(v.Value))), nil
	case dataTypeSID:
		return parseSID(v.Value)
	case dataTypeSecurityDescriptor:
		return parseSecurityDescriptor(v.Value)
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
		return parseV4AddrAndMask(v.Value), nil
	case dataTypeV6AddrMask:
		return parseV6AddrAndMask(v.Value), nil
	default:
		return nil, fmt.Errorf("unknown value type %d", v.Type)
	}
}

func parseV4AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v4 := *(*fwpV4AddrAndMask)(unsafe.Pointer(v))
	ip := netaddr.IPv4(uint8(v4.Addr>>24), uint8(v4.Addr>>16), uint8(v4.Addr>>8), uint8(v4.Addr))
	bits := uint8(32 - bits.TrailingZeros32(v4.Mask))
	return netaddr.IPPrefix{
		IP:   ip,
		Bits: bits,
	}
}

func parseV6AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v6 := *(*fwpV6AddrAndMask)(unsafe.Pointer(v))
	return netaddr.IPPrefix{
		IP:   netaddr.IPFrom16(v6.Addr),
		Bits: v6.PrefixLength,
	}
}

func parseSID(v *uintptr) (*windows.SID, error) {
	// TODO: export IsValidSid in x/sys/windows so we can vaguely
	// verify this pointer.
	sid := (*windows.SID)(unsafe.Pointer(v))
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
	bb := fromByteBlob(*(*fwpByteBlob)(unsafe.Pointer(v)))
	relSD := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&bb[0]))
	return relSD, nil
}

func ipv4From32(v uint32) netaddr.IP {
	return netaddr.IPv4(uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v))
}

func fromBytes(bb *uintptr, length int) []byte {
	var bs []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Cap = length
	sh.Len = length
	sh.Data = uintptr(unsafe.Pointer(bb))
	return append([]byte(nil), bs...)

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
