package wf

import (
	"errors"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LayerFlags are flags associated with a layer.
type LayerFlags uint32

const (
	LayerFlagsKernel         = 1 // classification occurs in kernel mode
	LayerFlagsBuiltin        = 2 // built-in layer, cannot be deleted
	LayerFlagsClassifyMostly = 4 // optimized for classifying not enumerating
	LayerFlagsBuffered       = 8 // buffered?
)

type FieldType uint32

const (
	FieldTypeRawData FieldType = iota
	FieldTypeIPAddress
	FieldTypeFlags
)

type SublayerFlags uint32

const SublayerFlagsPersistent = 1

type Layer struct {
	Key                windows.GUID
	ID                 uint16
	Name               string
	Description        string
	Flags              LayerFlags
	DefaultSublayerKey windows.GUID
	Fields             []*Field
}

type Field struct {
	Key      windows.GUID
	Type     FieldType
	DataType DataType
}

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

		var layers []*fwpmLayer0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(layersArray))

		for _, layer := range layers {
			var fields []fwpmField0
			sh = (*reflect.SliceHeader)(unsafe.Pointer(&fields))
			sh.Cap = int(layer.NumFields)
			sh.Len = int(layer.NumFields)
			sh.Data = uintptr(unsafe.Pointer(layer.Fields))

			l := &Layer{
				Key:                layer.LayerKey,
				ID:                 layer.LayerID,
				Name:               windows.UTF16PtrToString(layer.DisplayData.Name),
				Description:        windows.UTF16PtrToString(layer.DisplayData.Description),
				Flags:              layer.Flags,
				DefaultSublayerKey: layer.DefaultSublayerKey,
			}
			for _, field := range fields {
				l.Fields = append(l.Fields, &Field{
					Key:      *field.FieldKey,
					Type:     field.Type,
					DataType: field.DataType,
				})
			}
			ret = append(ret, l)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&layersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

type Sublayer struct {
	Key          windows.GUID
	Name         string
	Description  string
	Flags        SublayerFlags
	Provider     *windows.GUID // optional
	ProviderData []byte
	Weight       uint16
}

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

		var sublayers []*fwpmSublayer0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&sublayers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(sublayersArray))

		for _, sublayer := range sublayers {
			l := &Sublayer{
				Key:          sublayer.SublayerKey,
				Name:         windows.UTF16PtrToString(sublayer.DisplayData.Name),
				Description:  windows.UTF16PtrToString(sublayer.DisplayData.Description),
				Flags:        sublayer.Flags,
				Provider:     sublayer.ProviderKey,
				ProviderData: getByteBlob(sublayer.ProviderData),
				Weight:       sublayer.Weight,
			}
			ret = append(ret, l)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&sublayersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

func (s *Session) AddSublayer(sublayer *Sublayer) error {
	if sublayer.Key == (windows.GUID{}) {
		return errors.New("Sublayer.Key cannot be zero")
	}

	sl := fwpmSublayer0{
		SublayerKey:  sublayer.Key,
		DisplayData:  mkDisplayData(sublayer.Name, sublayer.Description),
		Flags:        sublayer.Flags,
		ProviderKey:  sublayer.Provider,
		ProviderData: mkByteBlob(sublayer.ProviderData),
		Weight:       sublayer.Weight,
	}

	return fwpmSubLayerAdd0(s.handle, &sl, nil)
}

func (s *Session) DeleteSublayer(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmSubLayerDeleteByKey0(s.handle, &id)
}

func mkDisplayData(name, description string) fwpmDisplayData0 {
	return fwpmDisplayData0{
		Name:        windows.StringToUTF16Ptr(name),
		Description: windows.StringToUTF16Ptr(description),
	}
}

func mkByteBlob(bs []byte) fwpByteBlob {
	if len(bs) == 0 {
		return fwpByteBlob{0, nil}
	}
	return fwpByteBlob{
		Size: uint32(len(bs)),
		Data: &bs[0],
	}
}

func getByteBlob(bb fwpByteBlob) []byte {
	if bb.Size == 0 {
		return nil
	}

	var blob []uint8
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size)
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))
	return append([]byte(nil), blob...)
}
