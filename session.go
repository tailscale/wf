package wf

import (
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
