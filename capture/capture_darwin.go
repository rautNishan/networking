package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// macOS (BSD) does not expose link-layer packet capture via AF_PACKET sockets like Linux.
// Instead, it uses BPF (Berkeley Packet Filter), exposed as character devices (/dev/bpf*).
// We iterate over these devices and open the first available one to capture raw packets.
// The kernel writes that copy into the BPF device buffer

// DOC: https://man.netbsd.org/bpf.4
func Open() (int, error) {
	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if err != unix.EBUSY {
			return -1, fmt.Errorf("failed to open %s: %w", path, err)
		}
	}
	return -1, fmt.Errorf("no free BPF device available")
}

// Doc: https://man7.org/linux/man-pages/man2/ioctl.2.html
func SetImmediate(fd int) error {
	val := 1
	//Why unsafe.Pointer => Because Go’s type system normally prevents mixing pointer types, but syscalls require raw memory pointers (like C’s char *argp) (ioctl)
	// More on unsafe.Pointer Doc: https://alexanderobregon.substack.com/p/unsafe-pointer-conversions-in-go
	if err := unix.IoctlSetInt(fd, unix.BIOCIMMEDIATE, val); err != nil { //unsafe.Pointer internally used (https://github.com/seccome/Ehoney/blob/3712e644d326466a7d64b1dec937064c6f7db8d7/tool/go/src/runtime/sys_openbsd3.go#L4)
		return fmt.Errorf("BIOCIMMEDIATE failed: %w", err)
	}
	return nil
}
