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

type dataType uint32

const (
	dataTypeEmpty                  dataType = 0
	dataTypeUint8                  dataType = 1
	dataTypeUint16                 dataType = 2
	dataTypeUint32                 dataType = 3
	dataTypeUint64                 dataType = 4
	dataTypeByteArray16            dataType = 11
	dataTypeByteBlob               dataType = 12
	dataTypeSID                    dataType = 13
	dataTypeSecurityDescriptor     dataType = 14
	dataTypeTokenInformation       dataType = 15
	dataTypeTokenAccessInformation dataType = 16
	dataTypeArray6                 dataType = 18
	dataTypeBitmapIndex            dataType = 19
	dataTypeV4AddrMask             dataType = 256
	dataTypeV6AddrMask             dataType = 257
	dataTypeRange                  dataType = 258
)

// Types not implemented, because WFP doesn't seem to use them.
// dataTypeInt8 dataType = 5
// dataTypeInt16 dataType = 6
// dataTypeInt32 dataType = 7
// dataTypeInt64 dataType = 8
// dataTypeFloat dataType = 9
// dataTypeDouble dataType = 10
// dataTypeUnicodeString dataType = 17
// dataTypeBitmapArray64 dataType = 20

type fwpmField0 struct {
	FieldKey *windows.GUID
	Type     fwpmFieldType
	DataType dataType
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

type fwpmProviderFlags uint32

const (
	fwpmProviderFlagsPersistent fwpmProviderFlags = 0x01
	fwpmProviderFlagsDisabled   fwpmProviderFlags = 0x10
)

type fwpmProvider0 struct {
	ProviderKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        fwpmProviderFlags
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

type fwpValue0 struct {
	Type  dataType
	Value *uintptr // unioned value
}

type fwpmFilterFlags uint32

const (
	fwpmFilterFlagsPersistent fwpmFilterFlags = 1 << iota
	fwpmFilterFlagsBootTime
	fwpmFilterFlagsHasProviderContext
	fwpmFilterFlagsClearActionRight
	fwpmFilterFlagsPermitIfCalloutUnregistered
	fwpmFilterFlagsDisabled
	fwpmFilterFlagsIndexed
)

type fwpmAction0 struct {
	Type Action
	GUID windows.GUID
}

type fwpmFilter0 struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData0
	Flags               fwpmFilterFlags
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            windows.GUID
	SublayerKey         windows.GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterConditions    *fwpmFilterCondition0
	Action              fwpmAction0
	ProviderContextKey  windows.GUID
	Reserved            *windows.GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

type fwpConditionValue0 struct {
	Type  dataType
	Value *uintptr
}

type fwpmFilterCondition0 struct {
	FieldKey  windows.GUID
	MatchType MatchType
	Value     fwpConditionValue0
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
	EnumType                filterEnumType
	Flags                   filterEnumFlags
	ProviderContextTemplate *fwpmProviderContextEnumTemplate0 // TODO: wtf?
	NumConditions           uint32
	Conditions              *fwpmFilterCondition0
	ActionMask              uint32
	CalloutKey              *windows.GUID
}

type fwpRange0 struct {
	From, To fwpValue0
}

type filterEnumType uint32

const (
	filterEnumTypeFullyContained filterEnumType = iota
	filterEnumTypeOverlapping
)

type filterEnumFlags uint32

const (
	filterEnumFlagsBestTerminatingMatch filterEnumFlags = iota + 1
	filterEnumFlagsSorted
	filterEnumFlagsBootTimeOnly
	filterEnumFlagsIncludeBootTime
	filterEnumFlagsIncludeDisabled
)
