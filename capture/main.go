package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

type WireEvent struct {
	// Identity
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`

	// Animation controls
	Kind          string `json:"kind"`           // "SYN"|"SYN-ACK"|"Data"|"FIN"|"FIN-ACK"|"RST"|"ACKOnly"|"UDP"
	Phase         string `json:"phase"`          // "Handshake"|"Established"|"Teardown"|"Closed"
	Direction     string `json:"direction"`      // "→"|"←"
	HandshakeStep int    `json:"handshake_step"` // 0–3
	Summary       string `json:"summary"`
	PayloadLen    int    `json:"payload_len"`

	// Flow key (canonical: higher port = client)
	ConnSrcIP   string `json:"conn_src_ip"`
	ConnDstIP   string `json:"conn_dst_ip"`
	ConnSrcPort uint16 `json:"conn_src_port"`
	ConnDstPort uint16 `json:"conn_dst_port"`

	// L1
	Medium   string `json:"medium"`
	LinkType uint32 `json:"link_type"`

	// L2 (omitempty = absent for loopback)
	EthSrcMAC    string `json:"eth_src_mac,omitempty"`
	EthDstMAC    string `json:"eth_dst_mac,omitempty"`
	EthEtherType string `json:"eth_ether_type,omitempty"`

	// L3
	NetVersion  string `json:"net_version,omitempty"`
	NetSrcIP    string `json:"net_src_ip,omitempty"`
	NetDstIP    string `json:"net_dst_ip,omitempty"`
	NetTTL      uint8  `json:"net_ttl,omitempty"`
	NetHopLimit uint8  `json:"net_hop_limit,omitempty"`
	NetProto    string `json:"net_proto,omitempty"`
	NetTotalLen uint16 `json:"net_total_len,omitempty"`

	// L4 TCP
	TCPSrcPort    uint16 `json:"tcp_src_port,omitempty"`
	TCPDstPort    uint16 `json:"tcp_dst_port,omitempty"`
	TCPSeqNum     uint32 `json:"tcp_seq_num,omitempty"`
	TCPAckNum     uint32 `json:"tcp_ack_num,omitempty"`
	TCPFlags      string `json:"tcp_flags,omitempty"`
	TCPWindowSize uint16 `json:"tcp_window_size,omitempty"`

	// L4 UDP
	UDPSrcPort uint16 `json:"udp_src_port,omitempty"`
	UDPDstPort uint16 `json:"udp_dst_port,omitempty"`
	UDPLength  uint16 `json:"udp_length,omitempty"`

	// L7
	AppProtocol      string `json:"app_proto,omitempty"`
	AppHTTPFirstLine string `json:"app_http_line,omitempty"`
	AppRawHex        string `json:"app_raw_hex,omitempty"`
	AppRawASCII      string `json:"app_raw_ascii,omitempty"`
}

var pktSeq uint64

func toWire(ev ConnectionEvent) WireEvent {
	w := WireEvent{
		ID:            fmt.Sprintf("pkt-%06d", atomic.AddUint64(&pktSeq, 1)),
		Timestamp:     ev.Timestamp.Format("15:04:05.000"),
		Kind:          ev.Kind.String(),
		Phase:         ev.Phase.String(),
		Direction:     ev.Direction.String(),
		HandshakeStep: int(ev.HandshakeStep),
		Summary:       ev.Summary,
		PayloadLen:    ev.PayloadLen,
		ConnSrcIP:     ev.ConnKey.SrcIP,
		ConnDstIP:     ev.ConnKey.DstIP,
		ConnSrcPort:   ev.ConnKey.SrcPort,
		ConnDstPort:   ev.ConnKey.DstPort,
		Medium:        ev.Packet.Physical.Medium,
		LinkType:      ev.Packet.Physical.LinkType,
	}
	pkt := ev.Packet
	if pkt.Ethernet != nil {
		w.EthSrcMAC = pkt.Ethernet.SrcMAC.String()
		w.EthDstMAC = pkt.Ethernet.DstMAC.String()
		w.EthEtherType = fmt.Sprintf("0x%04X", pkt.Ethernet.EtherType)
	}
	if pkt.Network != nil {
		w.NetSrcIP = pkt.Network.SrcIP().String()
		w.NetDstIP = pkt.Network.DstIP().String()
		w.NetProto = protocols[pkt.Network.Proto()]
		if pkt.Network.IPv4 != nil {
			w.NetVersion = "IPv4"
			w.NetTTL = pkt.Network.IPv4.TTL
			w.NetTotalLen = pkt.Network.IPv4.TotalLength
		} else {
			w.NetVersion = "IPv6"
			w.NetHopLimit = pkt.Network.IPv6.HopLimit
			w.NetTotalLen = pkt.Network.IPv6.PayloadLen
		}
	}
	if pkt.Transport != nil {
		if tcp := pkt.Transport.TCP; tcp != nil {
			w.TCPSrcPort = tcp.SrcPort
			w.TCPDstPort = tcp.DstPort
			w.TCPSeqNum = tcp.SeqNum
			w.TCPAckNum = tcp.AckNum
			w.TCPFlags = tcp.Flags.String()
			w.TCPWindowSize = tcp.WindowSize
		} else if udp := pkt.Transport.UDP; udp != nil {
			w.UDPSrcPort = udp.SrcPort
			w.UDPDstPort = udp.DstPort
			w.UDPLength = udp.Length
		}
	}
	if pkt.App != nil {
		w.AppProtocol = pkt.App.Protocol.String()
		w.AppHTTPFirstLine = pkt.App.HTTPFirstLine
		w.AppRawHex = pkt.App.RawHex
		w.AppRawASCII = pkt.App.RawASCII
	}
	return w
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*websocket.Conn]struct{})}
}

func (h *Hub) add(c *websocket.Conn) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// normal broadcast
func (h *Hub) broadcast(ev ConnectionEvent) {
	data, _ := json.Marshal(toWire(ev))

	h.mu.RLock()
	for c := range h.clients {
		_ = c.WriteMessage(websocket.TextMessage, data)
	}
	h.mu.RUnlock()
}

// paced broadcast (THIS creates sequential animation feel)
func (h *Hub) broadcastPaced(ev ConnectionEvent) {
	h.broadcast(ev)

	switch ev.Phase {
	case PhaseHandshake:
		time.Sleep(500 * time.Millisecond)
	case PhaseEstablished:
		time.Sleep(120 * time.Millisecond)
	case PhaseTeardown:
		time.Sleep(600 * time.Millisecond)
	}
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func wsHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("ws upgrade:", err)
			return
		}
		hub.add(conn)
		defer func() { hub.remove(conn); conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}
}

func captureLoop(iface string, portToFilter uint16, hub *Hub) {
	fd, err := Open()
	if err != nil {
		log.Fatal("BPF open:", err)
	}

	if err := BindInterface(fd, iface); err != nil {
		log.Fatal("BindInterface:", err)
	}

	linkType, err := GetLinkType(fd)
	if err != nil {
		log.Fatal("GetLinkType:", err)
	}

	if err := SetImmediate(fd); err != nil {
		log.Fatal("SetImmediate:", err)
	}

	buffLen, err := GetBuffLen(fd)
	if err != nil {
		log.Fatal("GetBuffLen:", err)
	}

	parser := NewParser(portToFilter)
	buf := make([]byte, buffLen)

	log.Printf("capturing on %s linkType=%d", iface, linkType)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			log.Println("read:", err)
			continue
		}

		events := parser.ParseRawData(buf[:n], linkType)

		for _, ev := range events {
			// fmt.Printf("Event: %v\n", ev)
			hub.broadcastPaced(ev)
		}
	}
}

func main() {
	iface := "lo0"
	portToFilter := uint16(3000)
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	if len(os.Args) > 2 {
		p, err := strconv.ParseUint(os.Args[2], 10, 16)
		if err != nil {
			log.Fatalf("invalid port: %v", err)
		}
		portToFilter = uint16(p)
	}
	fmt.Println("interface:", iface, "port:", portToFilter)

	hub := NewHub()
	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/ws", wsHandler(hub))

	go captureLoop(iface, portToFilter, hub)

	addr := ":8080"
	log.Printf("open http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
