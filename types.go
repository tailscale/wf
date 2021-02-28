package winfirewall

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

// LayerFlags are flags associated with a layer.
type LayerFlags uint32

const (
	LayerFlagsKernel             = 1 // classification occurs in kernel mode
	fwpmLayerFlagsBuiltin        = 2 // built-in layer, cannot be deleted
	fwpmLayerFlagsClassifyMostly = 4 // optimized for classifying not enumerating
	fwpmLayerFlagsBuffered       = 8 // buffered?
)

type fwpmLayer0 struct {
	LayerKey           windows.GUID
	DisplayData        fwpmDisplayData0
	Flags              LayerFlags
	NumFields          uint32
	Fields             *fwpmField0
	DefaultSublayerKey windows.GUID
	LayerID            uint16
}

type fwpmField0 struct {
	FieldKey *windows.GUID
	Type     FieldType
	DataType DataType
}

type FieldType uint32

const (
	FieldTypeRawData FieldType = iota
	FieldTypeIPAddress
	FieldTypeFlags
)

type DataType uint32

const (
	DataTypeEmpty DataType = iota
	DataTypeUint8
	DataTypeUint16
	DataTypeUint32
	DataTypeUint64
	DataTypeInt8
	DataTypeInt16
	DataTypeInt32
	DataTypeInt64
	DataTypeFloat
	DataTypeDouble
	DataTypeByteArray16
	DataTypeByteBlob
	DataTypeSID
	DataTypeSecurityDescriptor
	DataTypeTokenInformation
	DataTypeTokenAccessInformation
	DataTypeUnicodeString
	DataTypeV4AddrMask = 0x100 + iota
	DataTypeV6AddrMask
	DataTypeRange
)

type fwpmSublayerEnumTemplate0 struct {
	ProviderKey *windows.GUID
}

type SublayerFlags uint32

const SublayerFlagsPersistent = 1

type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

type fwpmSublayer0 struct {
	SublayerKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        SublayerFlags
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

type FilterFlags uint32

const (
	FilterFlagsPersistent FilterFlags = 1 << iota
	FilterFlagsBootTime
	FilterFlagsHasProviderContext
	FilterFlagsClearActionRight
	FilterFlagsPermitIfCalloutUnregistered
	FilterFlagsDisabled
	FilterFlagsIndexed
)

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

type ActionType uint32

const (
	ActionTypeBlock              ActionType = 0x1001
	ActionTypePermit                        = 0x1002
	ActionTypeCalloutTerminating            = 0x5003
	ActionTypeCalloutInspection             = 0x6004
	ActionTypeCalloutUnknown                = 0x4005
)

type MatchType uint32

const (
	MatchEqual MatchType = iota
	MatchGreater
	MatchLess
	MatchGreaterOrEqual
	MatchLessOrEqual
	MatchRange
	MatchFlagsAllSet
	MatchFlagsAnySet
	MatchFlagsNoneSet
	MatchEqualCaseInsensitive
	MatchNotEqual
	MatchPrefix
	MatchNotPrefix
)

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

type FilterEnumType uint32

const (
	FilterEnumTypeFullyContained FilterEnumType = iota
	FilterEnumTypeOverlapping
)

type FilterEnumFlags uint32

const (
	FilterEnumFlagsBestTerminatingMatch FilterEnumFlags = iota + 1
	FilterEnumFlagsSorted
	FilterEnumFlagsBootTimeOnly
	FilterEnumFlagsIncludeBootTime
	FilterEnumFlagsIncludeDisabled
)

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
