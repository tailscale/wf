package winfirewall

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Filter struct {
	Key                windows.GUID
	Name               string
	Description        string
	Flags              FilterFlags
	ProviderKey        *windows.GUID
	ProviderData       []byte
	LayerKey           windows.GUID
	SubLayerKey        windows.GUID
	Weight             Value
	Conditions         []Condition
	Action             Action
	ProviderContextKey windows.GUID
	Reserved           *windows.GUID
	FilterID           uint64
	EffectiveWeight    Value
}

type Condition struct {
	Field windows.GUID
	Op    MatchType
	Value Value
}

type Action struct {
	Type ActionType
	GUID windows.GUID
}

func (s *Session) Filters() ([]*Filter, error) {
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		fmt.Printf("%T\n", err)
		panic(err)
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*Filter

	const pageSize = 100
	for {
		var filtersArray **fwpmFilter0
		var num uint32
		if err := fwpmFilterEnum0(s.handle, enum, pageSize, &filtersArray, &num); err != nil {
			panic(err)
			return nil, err
		}

		var filters []*fwpmFilter0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&filters))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(filtersArray))

		for _, filter := range filters {
			f := &Filter{
				Key:                filter.FilterKey,
				Name:               windows.UTF16PtrToString(filter.DisplayData.Name),
				Description:        windows.UTF16PtrToString(filter.DisplayData.Description),
				Flags:              filter.Flags,
				ProviderKey:        filter.ProviderKey,
				ProviderData:       getByteBlob(filter.ProviderData),
				LayerKey:           filter.LayerKey,
				SubLayerKey:        filter.SubLayerKey,
				Weight:             nil, // TODO,
				Conditions:         nil, // TODO
				Action:             filter.Action,
				ProviderContextKey: filter.ProviderContextKey,
				FilterID:           filter.FilterID,
				EffectiveWeight:    nil, // TODO
			}
			ret = append(ret, f)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&filtersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}
