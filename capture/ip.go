package main

import "fmt"

// Resource :https://datatracker.ietf.org/doc/html/rfc791

// Also might be helpful
// (Does one ip packet contains multiple tcp segments ?)https://stackoverflow.com/questions/2220716/sending-multiple-tcp-packets-in-an-ip-packet

type Ip struct {
	packet []byte
}

func IpInit(data []byte) Ip {
	return Ip{
		packet: data,
	}
}

func (ip Ip) getVersion() string {
	firstByte := ip.packet[0]
	version := (firstByte & 0xF0) >> 4
	return fmt.Sprintf("%d", version)
}
