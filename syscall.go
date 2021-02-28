package winfirewall

//sys fwpmEngineOpen0(mustBeNil *uint16, authnService authnService, authIdentity *uintptr, session *fwpmSession0, engineHandle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmEngineOpen0

//sys fwpmEngineClose0(engineHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmEngineClose0

//sys fwpmLayerCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmLayerEnumTemplate0, handle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmLayerCreateEnumHandle0

//sys fwpmLayerDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmLayerDestroyEnumHandle0

//sys fwpmLayerEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmLayer0, numEntriesReturned *uint32) (err error) [failretval!=0] = fwpuclnt.FwpmLayerEnum0

//sys fwpmSubLayerCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmSublayerEnumTemplate0, handle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerCreateEnumHandle0

//sys fwpmSubLayerDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerDestroyEnumHandle0

//sys fwpmSubLayerEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmSublayer0, numEntriesReturned *uint32) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerEnum0

//sys fwpmFreeMemory0(p uintptr) = fwpuclnt.FwpmFreeMemory0

//sys fwpmSubLayerAdd0(engineHandle windows.Handle, sublayer *fwpmSublayer0, nilForNow *uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerAdd0

//sys fwpmSubLayerDeleteByKey0(engineHandle windows.Handle, guid *windows.GUID) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerDeleteByKey0

//sys fwpmProviderCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmProviderEnumTemplate0, handle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmProviderCreateEnumHandle0

//sys fwpmProviderDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmProviderDestroyEnumHandle0

//sys fwpmProviderEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmProvider0, numEntriesReturned *uint32) (err error) [failretval!=0] = fwpuclnt.FwpmProviderEnum0

//sys fwpmProviderAdd0(engineHandle windows.Handle, provider *fwpmProvider0, nilForNow *uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmProviderAdd0

//sys fwpmProviderDeleteByKey0(engineHandle windows.Handle, guid *windows.GUID) (err error) [failretval!=0] = fwpuclnt.FwpmProviderDeleteByKey0
