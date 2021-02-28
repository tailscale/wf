package winfirewall

import (
	"errors"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProviderFlags uint32

const (
	ProviderFlagsPersistent = 0x01
	ProviderFlagsDisabled   = 0x10
)

type Provider struct {
	Key          windows.GUID
	Name         string
	Description  string
	Flags        ProviderFlags
	ProviderData []byte
	ServiceName  string
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

		var providers []*fwpmProvider0
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&providers))
		sh.Cap = int(num)
		sh.Len = int(num)
		sh.Data = uintptr(unsafe.Pointer(providersArray))

		for _, provider := range providers {
			p := &Provider{
				Key:          provider.ProviderKey,
				Name:         windows.UTF16PtrToString(provider.DisplayData.Name),
				Description:  windows.UTF16PtrToString(provider.DisplayData.Description),
				Flags:        provider.Flags,
				ProviderData: getByteBlob(provider.ProviderData),
				ServiceName:  windows.UTF16PtrToString(provider.ServiceName),
			}
			ret = append(ret, p)
		}

		fwpmFreeMemory0(uintptr(unsafe.Pointer(&providersArray)))

		if num < pageSize {
			return ret, nil
		}
	}
}

func (s *Session) AddProvider(provider *Provider) error {
	if provider.Key == (windows.GUID{}) {
		return errors.New("Provider.Key cannot be zero")
	}

	p := &fwpmProvider0{
		ProviderKey:  provider.Key,
		DisplayData:  mkDisplayData(provider.Name, provider.Description),
		Flags:        provider.Flags,
		ProviderData: mkByteBlob(provider.ProviderData),
		ServiceName:  windows.StringToUTF16Ptr(provider.ServiceName),
	}

	return fwpmProviderAdd0(s.handle, p, nil)
}

func (s *Session) DeleteProvider(id windows.GUID) error {
	if id == (windows.GUID{}) {
		return errors.New("GUID cannot be zero")
	}

	return fwpmProviderDeleteByKey0(s.handle, &id)
}
