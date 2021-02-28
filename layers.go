package winfirewall

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Layer struct {
	Key                windows.GUID
	ID                 uint16
	Name               string
	Description        string
	Flags              LayerFlags
	DefaultSublayerKey windows.GUID
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
			ret = append(ret, &Layer{
				Key:                layer.LayerKey,
				ID:                 layer.LayerID,
				Name:               windows.UTF16PtrToString(layer.DisplayData.Name),
				Description:        windows.UTF16PtrToString(layer.DisplayData.Description),
				Flags:              layer.Flags,
				DefaultSublayerKey: layer.DefaultSublayerKey,
			})
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&layersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}
