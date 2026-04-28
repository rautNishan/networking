package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	Name [syscall.IFNAMSIZ]byte
	_    [16]byte
}

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
	EtherTypeVLAN = 0x8100
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
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, int(val)); err != nil { //unsafe.Pointer internally used (https://github.com/seccome/Ehoney/blob/3712e644d326466a7d64b1dec937064c6f7db8d7/tool/go/src/runtime/sys_openbsd3.go#L4)
		return fmt.Errorf("BIOCIMMEDIATE failed: %w", err)
	}
	return nil
}

func BindInterface(fd int, iface string) error {
	var req ifreq
	copy(req.Name[:], iface)

	_, _, errno := unix.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.BIOCSETIF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return fmt.Errorf("BIOCSETIF failed: %w", errno)
	}
	return nil
}

func GetBuffLen(fd int) (int, error) {
	var size uint32
	_, _, err := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&size)))
	if err != 0 {
		return 0, fmt.Errorf("BIOCGBLEN failed: %v", err)
	}
	return int(size), nil
}

// One Read() can return multiple packets — each prefixed by a BPF header.
func ParseRawData(data []byte) {
	offset := 0
	fmt.Println("Len of data: ", len(data))
	for offset < len(data) {
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&data[offset])) //reinterpret cast bytes to struct Go
		hdrLen := int(hdr.Hdrlen)
		capLen := int(hdr.Caplen)
		fmt.Println("Header len: ", hdrLen, " cap len: ", capLen)
		if hdrLen+capLen == 0 || offset+hdrLen+capLen > len(data) {
			break
		}
		frameStart := offset + hdrLen
		frameEnd := frameStart + capLen
		frame := data[frameStart:frameEnd]
		ParseFrame(frame)
		total := BPF_WORDALIGN(hdrLen + capLen)
		offset += total
	}
}

func BPF_WORDALIGN(x int) int {
	return (x + (unix.BPF_ALIGNMENT - 1)) & ^(unix.BPF_ALIGNMENT - 1) //https://stackoverflow.com/questions/34459450/what-is-the-operator-in-golang
}

func ParseFrame(frame []byte) { //https://www.geeksforgeeks.org/computer-networks/ethernet-frame-format/
	fmt.Println("This is a single frame: ", frame)
	macDst := net.HardwareAddr(frame[0:6])
	macSrc := net.HardwareAddr(frame[6:12])
	fmt.Println("Dst mac addr: ", macDst)
	fmt.Println("Src mac addr: ", macSrc)
	etherType := binary.BigEndian.Uint16(frame[12:14]) //The network byte order is defined to always be big-endian (https://www.ibm.com/docs/ja/zvm/7.2.0?topic=domains-network-byte-order-host-byte-order)
	switch etherType {
	case EtherTypeIPv6:
		fmt.Println("Ipv6")
		parseIpv6(frame[14:])
	case EtherTypeIPv4:
		fmt.Println("Ipv4")
		parseIPv4(frame[14:])
	default:
		fmt.Println("Some thing unknown: ", etherType)
	}
}

func parseIPv4(data []byte) {
	fmt.Println("Parsing this ipv4 data: ", data)
}

func parseIpv6(data []byte) {
	fmt.Println("Parsing this ipv6 data: ", data)
}
