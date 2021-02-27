package winfirewall

//go:generate go run generators/gen_guids.go includes/fwpmu.h zguids.go
//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall.go
