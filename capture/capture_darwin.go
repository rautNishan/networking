package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var protocols = map[uint8]string{
	1:   "ICMP",
	2:   "IGMP",
	6:   "TCP",
	17:  "UDP",
	41:  "ENCAP",
	89:  "OSPF",
	132: "SCTP",
}

const (
	ICMP  = 1
	IGMP  = 2
	TCP   = 6
	UDP   = 17
	ENCAP = 41
	OSPF  = 89
	SCTP  = 132
)

type IPv4Packet struct {
	ip             string
	Version        uint8
	IHL            uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	Identification uint16

	Flags          uint8
	FragmentOffset uint16

	TTL      uint8
	Protocol uint8

	HeaderChecksum uint16

	SrcIP net.IP
	DstIP net.IP

	Payload []byte
}
type IPv6Packet struct {
	ip           string
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
	Payload      []byte
}
type EthernetFrame struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16

	Payload []byte // IPv4 / IPv6 / others
}
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
	macDst := net.HardwareAddr(frame[0:6])
	macSrc := net.HardwareAddr(frame[6:12])
	etherType := binary.BigEndian.Uint16(frame[12:14]) //The network byte order is defined to always be big-endian (https://www.ibm.com/docs/ja/zvm/7.2.0?topic=domains-network-byte-order-host-byte-order)
	etherFrame := EthernetFrame{
		DstMAC:    macDst,
		SrcMAC:    macSrc,
		EtherType: etherType,
		Payload:   frame[14:],
	}
	fmt.Printf("%+v\n", etherFrame)
	switch etherFrame.EtherType {
	case EtherTypeIPv6:
		parseIpv6(etherFrame.Payload)
	case EtherTypeIPv4:
		parseIPv4(etherFrame.Payload)
	default:
		fmt.Println("Some thing unknown: ", etherFrame.EtherType)
	}
}

func parseIPv4(packets []byte) {
	if len(packets) < 20 {
		fmt.Println("To small to be IPV4")
		return
	}
	//parsing: https://www.tutorialspoint.com/ipv4/ipv4_packet_structure.htm
	firstByte := packets[0]

	version := firstByte >> 4 //Extract first 4 bits
	ihl := firstByte & 0x0F   //why 15 because its binayr is 1111 and we will only be needing last 4 bits

	secondByte := packets[1]
	dscp := secondByte >> 2
	ecn := secondByte & 0x03

	totalLen := binary.BigEndian.Uint16(packets[2:4])
	identification := binary.BigEndian.Uint16(packets[4:6]) //https://networkengineering.stackexchange.com/questions/46514/identification-field-in-ipv4-header

	flags := packets[6] >> 5
	fragmentOffset := (uint16(packets[6]&0x1F) << 8) | uint16(packets[7])

	ttl := packets[8]
	proto := packets[9]

	headerChecksum := binary.BigEndian.Uint16(packets[10:12])

	srcIP := net.IP(packets[12:16])
	dstIP := net.IP(packets[16:20])

	ipv4 := IPv4Packet{
		ip:             "IPV4",
		Version:        version,
		IHL:            ihl,
		DSCP:           dscp,
		ECN:            ecn,
		TotalLength:    totalLen,
		Identification: identification,
		Flags:          flags,
		FragmentOffset: fragmentOffset,
		TTL:            ttl,
		Protocol:       proto,
		HeaderChecksum: headerChecksum,
		SrcIP:          srcIP,
		DstIP:          dstIP,
		Payload:        packets[ihl*4:],
	}
	fmt.Printf("%+v\n", ipv4)
}

// IPv6 header is fixed at 40 bytes (unlike IPv4's variable IHL)
// https://www.geeksforgeeks.org/computer-networks/internet-protocol-version-6-ipv6-header/
func parseIpv6(packets []byte) {
	if len(packets) < 40 {
		fmt.Println("IPv6 packet too short")
		return
	}

	// First 4 bytes pack: version (4b), traffic class (8b), flow label (20b)
	firstWord := binary.BigEndian.Uint32(packets[0:4])

	version := uint8(firstWord >> 28)
	trafficClass := uint8((firstWord >> 20) & 0xFF)
	flowLabel := firstWord & 0x000FFFFF

	payloadLen := binary.BigEndian.Uint16(packets[4:6])
	nextHeader := packets[6]
	hopLimit := packets[7]

	srcIP := net.IP(packets[8:24])
	dstIP := net.IP(packets[24:40])

	ipv6 := IPv6Packet{
		ip:           "IPV6",
		Version:      version,
		TrafficClass: trafficClass,
		FlowLabel:    flowLabel,
		PayloadLen:   payloadLen,
		NextHeader:   nextHeader,
		HopLimit:     hopLimit,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		Payload:      packets[40:],
	}

	fmt.Printf("%+v\n", ipv6)

	// NextHeader reuses the same protocol numbers as IPv4's Protocol field
	if name, ok := protocols[nextHeader]; ok {
		fmt.Printf("Next Header Protocol: %s\n", name)
	} else {
		fmt.Printf("Next Header Protocol: unknown (%d)\n", nextHeader)
	}
}
