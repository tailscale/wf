package wf

import (
	"golang.org/x/sys/windows"
)

type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

type fwpmSession0Flags uint32

const fwpmSession0FlagDynamic = 1

type fwpmSession0 struct {
	SessionKey           windows.GUID
	DisplayData          fwpmDisplayData0
	Flags                fwpmSession0Flags
	TxnWaitTimeoutMillis uint32
	ProcessID            uint32
	SID                  *windows.SID
	Username             *uint16
	KernelMode           uint8
}

type authnService uint32

const (
	authnServiceWinNT   authnService = 0xa
	authnServiceDefault authnService = 0xffffffff
)

type fwpmLayerEnumTemplate0 struct {
	reserved uint64
}

type fwpmLayerFlags uint32

const (
	fwpmLayerFlagsKernel fwpmLayerFlags = 1 << iota
	fwpmLayerFlagsBuiltin
	fwpmLayerFlagsClassifyMostly
	fwpmLayerFlagsBuffered
)

type fwpmLayer0 struct {
	LayerKey           windows.GUID
	DisplayData        fwpmDisplayData0
	Flags              fwpmLayerFlags
	NumFields          uint32
	Fields             *fwpmField0
	DefaultSublayerKey windows.GUID
	LayerID            uint16
}

type fwpmFieldType uint32

const (
	fwpmFieldTypeRawData   fwpmFieldType = iota // no special semantics
	fwpmFieldTypeIPAddress                      // data is an IP address
	fwpmFieldTypeFlags                          // data is a flag bitfield
)

type fwpmField0 struct {
	FieldKey *windows.GUID
	Type     fwpmFieldType
	DataType DataType
}

type fwpmSublayerEnumTemplate0 struct {
	ProviderKey *windows.GUID
}

type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

type fwpmSublayerFlags uint32

const fwpmSublayerFlagsPersistent fwpmSublayerFlags = 1

type fwpmSublayer0 struct {
	SublayerKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        fwpmSublayerFlags
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob
	Weight       uint16
}

type fwpmProviderEnumTemplate0 struct {
	Reserved uint64
}

type fwpmProvider0 struct {
	ProviderKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        ProviderFlags
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

type fwpValue0 struct {
	Type  DataType
	Value uintptr // unioned value
}

type fwpmFilter0 struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData0
	Flags               FilterFlags
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterConditions    *fwpmFilterCondition0
	Action              Action
	ProviderContextKey  windows.GUID
	Reserved            *windows.GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

type fwpConditionValue0 struct {
	Type  DataType
	Value uintptr
}

type fwpmFilterCondition0 struct {
	FieldKey       windows.GUID
	MatchType      MatchType
	ConditionValue fwpConditionValue0
}

type fwpV4AddrAndMask struct {
	Addr, Mask uint32
}

type fwpV6AddrAndMask struct {
	Addr         [16]byte
	PrefixLength uint8
}

type fwpmProviderContextEnumTemplate0 struct {
	ProviderKey         *windows.GUID
	ProviderContextType uint32
}

type fwpmFilterEnumTemplate0 struct {
	ProviderKey             *windows.GUID
	LayerKey                windows.GUID
	EnumType                FilterEnumType
	Flags                   FilterEnumFlags
	ProviderContextTemplate *fwpmProviderContextEnumTemplate0 // TODO: wtf?
	NumConditions           uint32
	Conditions              *fwpmFilterCondition0
	ActionMask              uint32
	CalloutKey              *windows.GUID
}
