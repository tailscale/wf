package winfirewall

//sys fwpmEngineOpen0(mustBeNil *uint16, authnService authnService, authIdentity *uintptr, session *fwpmSession0, engineHandle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmEngineOpen0

//sys fwpmEngineClose0(engineHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmEngineClose0

//sys fwpmLayerCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmLayerEnumTemplate0, handle *windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmLayerCreateEnumHandle0

//sys fwpmLayerDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (err error) [failretval!=0] = fwpuclnt.FwpmLayerDestroyEnumHandle0

//sys fwpmLayerEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmLayer0, numEntriesReturned *uint32) (err error) [failretval!=0] = fwpuclnt.FwpmLayerEnum0

//sys fwpmFreeMemory0(p uintptr) = fwpuclnt.FwpmFreeMemory0
