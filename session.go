package winfirewall

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	handle windows.Handle
}

func New() (*Session, error) {
	session := fwpmSession0{
		DisplayData: fwpmDisplayData0{
			Name:        windows.StringToUTF16Ptr("test"),
			Description: windows.StringToUTF16Ptr("test description"),
		},
		Flags:                fwpmSession0FlagDynamic,
		TxnWaitTimeoutMillis: windows.INFINITE,
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

func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	return fwpmEngineClose0(s.handle)
}

func (s *Session) Test() error {
	var enumHandle windows.Handle
	if err := fwpmLayerCreateEnumHandle0(s.handle, nil, &enumHandle); err != nil {
		return err
	}
	defer fwpmLayerDestroyEnumHandle0(s.handle, enumHandle)

	var layersArray **fwpmLayer0
	var numLayers uint32
	if err := fwpmLayerEnum0(s.handle, enumHandle, 1000, &layersArray, &numLayers); err != nil {
		return err
	}
	defer fwpmFreeMemory0((**uintptr)(unsafe.Pointer(layersArray)))

	var layers []*fwpmLayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
	sh.Cap = int(numLayers)
	sh.Len = int(numLayers)
	sh.Data = uintptr(unsafe.Pointer(layersArray))

	for i, layer := range layers {
		fmt.Printf("%d\n%#v\n%s\n%s\n%s\n%s\n\n", i, *layer, guidNames[layer.LayerKey], guidNames[layer.DefaultSubLayerKey], windows.UTF16PtrToString(layer.DisplayData.Name), windows.UTF16PtrToString(layer.DisplayData.Name))
	}

	return nil
}
