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
	DataTypeUint6
	DataTypeUint2
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
