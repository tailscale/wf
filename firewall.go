package wf

import (
	"errors"
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
)

// GUIDName returns a human-readable name for standard WFP GUIDs. If g
// is not a standard WFP GUID, g.String() is returned.
func GUIDName(g windows.GUID) string {
	if n := guidNames[g]; n != "" {
		return n
	}
	return g.String()
}

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

	var a arena
	defer a.dispose()

	s0 := toSession0(&a, opts)

	var handle windows.Handle
	err := fwpmEngineOpen0(nil, authnServiceWinNT, nil, s0, &handle)
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

// TokenAccessInformation represents all the information in a token
// that is necessary to perform an access check.
// This type is only present in Layer fields, and cannot be used
// directly as a value in firewall rules.
type TokenAccessInformation struct{}

// BitmapIndex is an index into a Bitmap64.
type BitmapIndex uint8 // TODO: this is a guess, the API doesn't document what the underlying type is.

type Range struct {
	From, To interface{}
}

// TokenInformation defines a set of security identifiers.
// This type is only present in Layer fields, and cannot be used
// directly as a value in firewall rules.
type TokenInformation struct{}

// Layers returns information on available WFP layers.
func (s *Session) Layers() ([]*Layer, error) {
	var enum windows.Handle
	if err := fwpmLayerCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Layer

	for {
		layers, err := s.getLayerPage(enum)
		if err != nil {
			return nil, err
		}
		if len(layers) == 0 {
			return ret, nil
		}
		ret = append(ret, layers...)
	}
}

func (s *Session) getLayerPage(enum windows.Handle) ([]*Layer, error) {
	const pageSize = 103
	var (
		array **fwpmLayer0
		num   uint32
	)
	if err := fwpmLayerEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromLayer0(array, num)
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
	var a arena
	defer a.dispose()

	tpl := toSublayerEnumTemplate0(&a, provider)

	var enum windows.Handle
	if err := fwpmSubLayerCreateEnumHandle0(s.handle, tpl, &enum); err != nil {
		return nil, err
	}
	defer fwpmSubLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Sublayer

	for {
		sublayers, err := s.getSublayerPage(enum)
		if err != nil {
			return nil, err
		}
		if len(sublayers) == 0 {
			return ret, nil
		}
		ret = append(ret, sublayers...)
	}
}

func (s *Session) getSublayerPage(enum windows.Handle) ([]*Sublayer, error) {
	const pageSize = 100
	var (
		array **fwpmSublayer0
		num   uint32
	)
	if err := fwpmSubLayerEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromSublayer0(array, num), nil
}

// AddSublayer creates a new Sublayer.
func (s *Session) AddSublayer(sl *Sublayer) error {
	// the WFP API accepts zero GUIDs and interprets it as "give me a
	// random GUID". However, we can't get that GUID back out, so it
	// would be pointless to make such a request. Stop it here.
	if sl.Key == (windows.GUID{}) {
		return errors.New("Sublayer.Key cannot be zero")
	}

	var a arena
	defer a.dispose()

	sl0 := toSublayer0(&a, sl)
	return fwpmSubLayerAdd0(s.handle, sl0, nil) // TODO: security descriptor
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

	for {
		providers, err := s.getProviderPage(enum)
		if err != nil {
			return nil, err
		}
		if len(providers) == 0 {
			return ret, nil
		}
		ret = append(ret, providers...)
	}
}

func (s *Session) getProviderPage(enum windows.Handle) ([]*Provider, error) {
	const pageSize = 100
	var (
		array **fwpmProvider0
		num   uint32
	)
	if err := fwpmProviderEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromProvider0(array, num), nil
}

// AddProvider creates a new provider.
func (s *Session) AddProvider(p *Provider) error {
	if p.Key == (windows.GUID{}) {
		return errors.New("Provider.Key cannot be zero")
	}

	var a arena
	defer a.dispose()

	p0 := toProvider0(&a, p)

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
		rules, err := s.getRulePage(enum)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return ret, nil
		}
		ret = append(ret, rules...)
	}
}

func (s *Session) getRulePage(enum windows.Handle) ([]*Rule, error) {
	const pageSize = 100
	var (
		array **fwpmFilter0
		num   uint32
	)
	if err := fwpmFilterEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromFilter0(array, num, s.layerTypes)
}

func (s *Session) AddRule(r *Rule) error {
	if r.Key == (windows.GUID{}) {
		return errors.New("Provider.Key cannot be zero")
	}

	var a arena
	defer a.dispose()

	f, err := toFilter0(&a, r, s.layerTypes)
	if err != nil {
		return err
	}

	if err := fwpmFilterAdd0(s.handle, f, nil, nil); err != nil {
		return err
	}

	return nil
}
