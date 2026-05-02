package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ─── Protocol constants ──────────────────────────────────────────

var protocols = map[uint8]string{
	1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
	41: "ENCAP", 89: "OSPF", 132: "SCTP",
}

const (
	DLT_NULL   = 0
	DLT_EN10MB = 1
)
const (
	ICMP  = 1
	IGMP  = 2
	TCP   = 6
	UDP   = 17
	ENCAP = 41
	OSPF  = 89
	SCTP  = 132
)
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
	EtherTypeVLAN = 0x8100
)

type ifreq struct {
	Name [syscall.IFNAMSIZ]byte
	_    [16]byte
}

// macOS (BSD) does not expose link-layer packet capture via AF_PACKET sockets like Linux.
// Instead, it uses BPF (Berkeley Packet Filter), exposed as character devices (/dev/bpf*).
// We iterate over these devices and open the first available one to capture raw packets.
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
	_, _, errno := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return fmt.Errorf("BIOCSETIF failed: %w", errno)
	}
	return nil
}

func GetLinkType(fd int) (uint32, error) {
	var linkType uint32
	_, _, errno := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCGDLT), uintptr(unsafe.Pointer(&linkType)))
	if errno != 0 {
		return 0, fmt.Errorf("BIOCGDLT failed: %w", errno)
	}
	return linkType, nil
}

func GetBuffLen(fd int) (int, error) {
	var size uint32
	_, _, err := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&size)))
	if err != 0 {
		return 0, fmt.Errorf("BIOCGBLEN failed: %v", err)
	}
	return int(size), nil
}

func BPF_WORDALIGN(x int) int {
	return (x + (unix.BPF_ALIGNMENT - 1)) & ^(unix.BPF_ALIGNMENT - 1) //https://stackoverflow.com/questions/34459450/what-is-the-operator-in-golang
}

type PhysicalLayer struct {
	Medium   string // "Ethernet" | "Loopback"
	LinkType uint32
}

type EthernetLayer struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	EtherType uint16
}

type IPv4Layer struct {
	Version        uint8
	IHL            uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP          net.IP
	DstIP          net.IP
}

type IPv6Layer struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

type NetworkLayer struct {
	IPv4 *IPv4Layer
	IPv6 *IPv6Layer
}

func (n *NetworkLayer) SrcIP() net.IP {
	if n.IPv4 != nil {
		return n.IPv4.SrcIP
	}
	return n.IPv6.SrcIP
}
func (n *NetworkLayer) DstIP() net.IP {
	if n.IPv4 != nil {
		return n.IPv4.DstIP
	}
	return n.IPv6.DstIP
}
func (n *NetworkLayer) Proto() uint8 {
	if n.IPv4 != nil {
		return n.IPv4.Protocol
	}
	return n.IPv6.NextHeader
}

type TCPFlags struct {
	CWR, ECE, URG, ACK, PSH, RST, SYN, FIN bool
}

func (f TCPFlags) String() string {
	var parts []string
	for _, p := range []struct {
		set  bool
		name string
	}{
		{f.SYN, "SYN"}, {f.ACK, "ACK"}, {f.FIN, "FIN"},
		{f.RST, "RST"}, {f.PSH, "PSH"}, {f.URG, "URG"},
		{f.ECE, "ECE"}, {f.CWR, "CWR"},
	} {
		if p.set {
			parts = append(parts, p.name)
		}
	}
	return strings.Join(parts, "|")
}

type TCPLayer struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      TCPFlags
	WindowSize uint16
	Checksum   uint16
	Options    []byte
	Payload    []byte
}

type UDPLayer struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

type TransportLayer struct {
	TCP *TCPLayer
	UDP *UDPLayer
}

func (t *TransportLayer) SrcPort() uint16 {
	if t.TCP != nil {
		return t.TCP.SrcPort
	}
	return t.UDP.SrcPort
}
func (t *TransportLayer) DstPort() uint16 {
	if t.TCP != nil {
		return t.TCP.DstPort
	}
	return t.UDP.DstPort
}

type AppProtocol uint8

const (
	AppUnknown AppProtocol = iota
	AppHTTP
	AppHTTPS
	AppDNS
	AppRaw
)

func (a AppProtocol) String() string {
	return [...]string{"Unknown", "HTTP", "HTTPS/TLS", "DNS", "Raw"}[a]
}

type AppLayer struct {
	Protocol      AppProtocol
	HTTPFirstLine string
	RawHex        string
	RawASCII      string
}

type ParsedPacket struct {
	CapturedAt time.Time
	FrameSize  int
	Physical   PhysicalLayer
	Ethernet   *EthernetLayer
	Network    *NetworkLayer
	Transport  *TransportLayer
	App        *AppLayer
}

type ConnKey struct {
	SrcIP, DstIP string
	SrcPort      uint16
	DstPort      uint16
	Proto        uint8
}

func (p *ParsedPacket) ConnKey() (ConnKey, bool) {
	if p.Network == nil || p.Transport == nil {
		return ConnKey{}, false
	}
	src := p.Network.SrcIP().String()
	dst := p.Network.DstIP().String()
	sp := p.Transport.SrcPort()
	dp := p.Transport.DstPort()
	proto := p.Network.Proto()
	if sp < dp {
		src, dst = dst, src
		sp, dp = dp, sp
	}
	return ConnKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: proto}, true
}

type ConnectionPhase uint8

const (
	PhaseHandshake ConnectionPhase = iota
	PhaseEstablished
	PhaseTeardown
	PhaseClosed
)

func (p ConnectionPhase) String() string {
	return [...]string{"Handshake", "Established", "Teardown", "Closed"}[p]
}

type HandshakeStep uint8

const (
	StepNone HandshakeStep = iota
	StepSYN
	StepSYNACK
	StepACK
)

type ConnectionEventKind uint8

const (
	EvtSYN ConnectionEventKind = iota
	EvtSYNACK
	EvtData
	EvtFIN
	EvtFINACK
	EvtRST
	EvtACKOnly
	EvtWindowUpdate
	EvtUDP
)

func (e ConnectionEventKind) String() string {
	return [...]string{
		"SYN", "SYN-ACK",
		"Data", "FIN", "FIN-ACK", "RST", "ACK", "WindowUpdate (ACK)", "UDP",
	}[e]
}

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

func (d Direction) String() string {
	if d == ClientToServer {
		return "→"
	}
	return "←"
}

type ConnectionEvent struct {
	Kind          ConnectionEventKind
	Phase         ConnectionPhase
	Direction     Direction
	HandshakeStep HandshakeStep
	Timestamp     time.Time
	PayloadLen    int
	Summary       string
	ConnKey       ConnKey
	Packet        *ParsedPacket
}

// connection tracks per-connection state for classification.
//
// expectServerWindowUpdate:
//
//	Set to true when the client sends the final handshake ACK
//	(SYN → SYN-ACK → ACK). The very next ACK from the server
//	(no payload, no SYN/FIN) is a TCP window update — the server
//	is advertising its receive buffer now that the connection is
//	fully established. We consume the flag immediately so that
//	any subsequent server ACKs (e.g. ACK-ing a client request)
//	are classified normally.
type connection struct {
	phase     ConnectionPhase
	handshake HandshakeStep
	bytesSent int
	bytesRecv int

	// Set true after the third handshake ACK (client→server).
	// Consumed (set false) the moment the first server ACK arrives.
	expectServerWindowUpdate bool
}

// ─── Parser ──────────────────────────────────────────────────────

type Parser struct {
	conns      map[ConnKey]*connection
	FilterPort uint16
}

func NewParser(filterPort uint16) *Parser {
	return &Parser{
		conns:      make(map[ConnKey]*connection),
		FilterPort: filterPort,
	}
}

// ParseRawData processes a BPF read buffer which may contain multiple packets.
func (p *Parser) ParseRawData(data []byte, linkType uint32) []ConnectionEvent {
	var events []ConnectionEvent
	offset := 0
	for offset < len(data) {
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&data[offset])) //reinterpret cast bytes to struct Go
		hdrLen := int(hdr.Hdrlen)
		capLen := int(hdr.Caplen)
		if hdrLen+capLen == 0 || offset+hdrLen+capLen > len(data) {
			break
		}
		frame := data[offset+hdrLen : offset+hdrLen+capLen]
		if ev, ok := p.parseFrame(frame, linkType, capLen); ok {
			events = append(events, ev)
		}
		offset += BPF_WORDALIGN(hdrLen + capLen)
	}
	return events
}

func (p *Parser) parseFrame(frame []byte, linkType uint32, size int) (ConnectionEvent, bool) {
	//https://www.geeksforgeeks.org/computer-networks/ethernet-frame-format/
	pkt := &ParsedPacket{
		CapturedAt: time.Now(),
		FrameSize:  size,
		Physical:   PhysicalLayer{LinkType: linkType, Medium: "Ethernet"},
	}

	if linkType == DLT_NULL {
		pkt.Physical.Medium = "Loopback"
		if len(frame) < 4 {
			return ConnectionEvent{}, false
		}
		afFamily := *(*uint32)(unsafe.Pointer(&frame[0]))
		payload := frame[4:]
		switch afFamily {
		case unix.AF_INET:
			if !p.parseIPv4(payload, pkt) {
				return ConnectionEvent{}, false
			}
		case unix.AF_INET6:
			if !p.parseIPv6(payload, pkt) {
				return ConnectionEvent{}, false
			}
		default:
			return ConnectionEvent{}, false
		}
	} else {
		if len(frame) < 14 {
			return ConnectionEvent{}, false
		}
		eth := &EthernetLayer{
			DstMAC:    net.HardwareAddr(frame[0:6]),
			SrcMAC:    net.HardwareAddr(frame[6:12]),
			EtherType: binary.BigEndian.Uint16(frame[12:14]), //The network byte order is defined to always be big-endian (https://www.ibm.com/docs/ja/zvm/7.2.0?topic=domains-network-byte-order-host-byte-order)
		}
		pkt.Ethernet = eth
		payload := frame[14:]
		switch eth.EtherType {
		case EtherTypeIPv4:
			if !p.parseIPv4(payload, pkt) {
				return ConnectionEvent{}, false
			}
		case EtherTypeIPv6:
			if !p.parseIPv6(payload, pkt) {
				return ConnectionEvent{}, false
			}
		default:
			return ConnectionEvent{}, false
		}
	}

	if p.FilterPort != 0 && pkt.Transport != nil {
		sp, dp := pkt.Transport.SrcPort(), pkt.Transport.DstPort()
		if sp != p.FilterPort && dp != p.FilterPort {
			return ConnectionEvent{}, false
		}
	}

	return p.classify(pkt)
}

func (p *Parser) parseIPv4(data []byte, pkt *ParsedPacket) bool { //https://www.geeksforgeeks.org/computer-networks/tcp-ip-packet-format/
	if len(data) < 20 {
		return false
	}
	//parsing: https://www.tutorialspoint.com/ipv4/ipv4_packet_structure.htm

	ihl := data[0] & 0x0F
	layer := &IPv4Layer{
		Version:        data[0] >> 4,
		IHL:            ihl,
		DSCP:           data[1] >> 2,
		ECN:            data[1] & 0x03,
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		Identification: binary.BigEndian.Uint16(data[4:6]), //https://networkengineering.stackexchange.com/questions/46514/identification-field-in-ipv4-header
		Flags:          data[6] >> 5,
		FragmentOffset: (uint16(data[6]&0x1F) << 8) | uint16(data[7]),
		TTL:            data[8],
		Protocol:       data[9],
		HeaderChecksum: binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DstIP:          net.IP(data[16:20]),
	}
	pkt.Network = &NetworkLayer{IPv4: layer}
	headerEnd := int(ihl) * 4
	if headerEnd > len(data) {
		return false
	}
	return p.parseTransport(data[headerEnd:], layer.Protocol, pkt)
}

// IPv6 header is fixed at 40 bytes (unlike IPv4's variable IHL)
// https://www.geeksforgeeks.org/computer-networks/internet-protocol-version-6-ipv6-header/
func (p *Parser) parseIPv6(data []byte, pkt *ParsedPacket) bool {
	if len(data) < 40 {
		return false
	}
	firstWord := binary.BigEndian.Uint32(data[0:4]) // First 4 bytes pack: version (4b), traffic class (8b), flow label (20b)
	layer := &IPv6Layer{
		Version:      uint8(firstWord >> 28),
		TrafficClass: uint8((firstWord >> 20) & 0xFF),
		FlowLabel:    firstWord & 0x000FFFFF,
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
		SrcIP:        net.IP(data[8:24]),
		DstIP:        net.IP(data[24:40]),
	}
	pkt.Network = &NetworkLayer{IPv6: layer}
	return p.parseTransport(data[40:], layer.NextHeader, pkt)
}

func (p *Parser) parseTransport(data []byte, proto uint8, pkt *ParsedPacket) bool {
	switch proto {
	case TCP:
		return p.parseTCP(data, pkt)
	case UDP:
		return p.parseUDP(data, pkt)
	}
	return false
}

func (p *Parser) parseTCP(data []byte, pkt *ParsedPacket) bool { //https://support.huawei.com/enterprise/en/doc/EDOC1100174721/ecc2fe2f/tcp
	if len(data) < 20 {
		return false
	}
	dataOffset := data[12] >> 4
	if dataOffset < 5 || dataOffset > 15 {
		return false
	}
	hdrEnd := int(dataOffset) * 4
	if hdrEnd > len(data) {
		return false
	}
	f := data[13]
	layer := &TCPLayer{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: dataOffset,
		Flags: TCPFlags{
			CWR: f>>7&1 == 1, ECE: f>>6&1 == 1, URG: f>>5&1 == 1,
			ACK: f>>4&1 == 1, PSH: f>>3&1 == 1, RST: f>>2&1 == 1,
			SYN: f>>1&1 == 1, FIN: f&1 == 1,
		},
		WindowSize: binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Options:    data[20:hdrEnd],
		Payload:    data[hdrEnd:],
	}
	// b, _ := json.MarshalIndent(layer, "", "  ")
	// fmt.Println(string(b))
	pkt.Transport = &TransportLayer{TCP: layer}
	if len(layer.Payload) > 0 {
		p.parseApp(layer.Payload, layer.DstPort, pkt)
	}
	return true
}

func (p *Parser) parseUDP(data []byte, pkt *ParsedPacket) bool {
	if len(data) < 8 {
		return false
	}
	layer := &UDPLayer{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[8:],
	}
	pkt.Transport = &TransportLayer{UDP: layer}
	if len(layer.Payload) > 0 {
		p.parseApp(layer.Payload, layer.DstPort, pkt)
	}
	return true
}

func (p *Parser) parseApp(payload []byte, dstPort uint16, pkt *ParsedPacket) {
	app := &AppLayer{}
	if len(payload) >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
		app.Protocol = AppHTTPS
		pkt.App = app
		return
	}
	if dstPort == 53 {
		app.Protocol = AppDNS
		pkt.App = app
		return
	}
	line := firstLineOf(payload)
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/"} {
		if strings.HasPrefix(line, prefix) {
			app.Protocol = AppHTTP
			app.HTTPFirstLine = strings.TrimRight(line, "\r\n")
			pkt.App = app
			return
		}
	}
	preview := payload
	if len(preview) > 128 {
		preview = preview[:128]
	}
	app.Protocol = AppRaw
	app.RawHex = fmt.Sprintf("%x", preview)
	app.RawASCII = toASCII(preview)
	pkt.App = app
}

func (p *Parser) classify(pkt *ParsedPacket) (ConnectionEvent, bool) {
	key, ok := pkt.ConnKey()
	if !ok {
		return ConnectionEvent{}, false
	}

	dir := ClientToServer
	if pkt.Transport != nil && pkt.Transport.SrcPort() == key.DstPort {
		dir = ServerToClient
	}

	ev := ConnectionEvent{
		Packet:    pkt,
		ConnKey:   key,
		Direction: dir,
		Timestamp: pkt.CapturedAt,
	}

	if pkt.Transport != nil && pkt.Transport.UDP != nil {
		ev.Kind = EvtUDP
		ev.Phase = PhaseEstablished
		ev.PayloadLen = len(pkt.Transport.UDP.Payload)
		ev.Summary = "UDP"
		return ev, true
	}

	tcp := pkt.Transport.TCP
	fl := tcp.Flags

	conn := p.conns[key]
	if conn == nil {
		conn = &connection{}
		p.conns[key] = conn
	}

	switch {

	case fl.SYN && !fl.ACK:
		conn.phase = PhaseHandshake
		conn.handshake = StepSYN
		ev.Kind = EvtSYN
		ev.Phase = PhaseHandshake
		ev.HandshakeStep = StepSYN
		ev.Summary = "SYN"

	case fl.SYN && fl.ACK:
		conn.handshake = StepSYNACK
		ev.Kind = EvtSYNACK
		ev.Phase = PhaseHandshake
		ev.HandshakeStep = StepSYNACK
		ev.Summary = "SYN-ACK"

	case fl.FIN:
		conn.phase = PhaseTeardown
		ev.Kind = EvtFIN
		ev.Phase = PhaseTeardown
		ev.Summary = "FIN"

	case len(tcp.Payload) > 0 && dir == ServerToClient:
		conn.phase = PhaseEstablished
		ev.Kind = EvtData
		ev.Phase = PhaseEstablished
		ev.PayloadLen = len(tcp.Payload)
		ev.Summary = "DATA"

	case len(tcp.Payload) > 0 && dir == ClientToServer:
		conn.phase = PhaseEstablished
		ev.Kind = EvtData
		ev.Phase = PhaseEstablished
		ev.PayloadLen = len(tcp.Payload)
		ev.Summary = "REQUEST"

	default:
		ev.Phase = conn.phase

		// Third handshake ACK: client → server, no payload
		// This completes the three-way handshake.
		// Flag the connection so the very next server ACK is
		// treated as a window update, then fall through to ACKOnly.
		if dir == ClientToServer && conn.handshake == StepSYNACK {
			conn.handshake = StepACK
			conn.phase = PhaseEstablished
			ev.Phase = PhaseEstablished
			conn.expectServerWindowUpdate = true // ← arm the flag
			ev.Kind = EvtACKOnly
			ev.Summary = "ACK (handshake complete)"
			break
		}

		// First server ACK after handshake = window update
		// The server is advertising its receive buffer now that the
		// connection is fully established. We consume the flag
		// immediately so subsequent server ACKs (e.g. ACK-ing a
		// client HTTP request) are classified as plain ACKs.
		if dir == ServerToClient && conn.expectServerWindowUpdate {
			conn.expectServerWindowUpdate = false
			ev.Kind = EvtWindowUpdate
			ev.Summary = fmt.Sprintf("(ACK) WINDOW UPDATE (win=%d)", tcp.WindowSize)
			break
		}

		ev.Kind = EvtACKOnly
		ev.Summary = "ACK"
	}

	return ev, true
}

func firstLineOf(b []byte) string {
	for i, c := range b {
		if c == '\n' || i == 512 {
			return string(b[:i])
		}
	}
	return string(b)
}

func toASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
