package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	iface := "lo0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	fmt.Println("Used interface:", iface)

	fd, err := Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error in open:", err)
		os.Exit(1)
	}

	if err := BindInterface(fd, iface); err != nil {
		fmt.Fprintln(os.Stderr, "Error while binding interface:", err)
		os.Exit(1)
	}

	linkType, err := GetLinkType(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting link type:", err)
		os.Exit(1)
	}
	fmt.Println("Link type:", linkType)

	if err := SetImmediate(fd); err != nil {
		fmt.Fprintln(os.Stderr, "Error in set immediate:", err)
		os.Exit(1)
	}

	buffLen, err := GetBuffLen(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while getting buffer length:", err)
		os.Exit(1)
	}
	fmt.Println("This is buffer size: ", buffLen)
	buffer := make([]byte, buffLen)

	for {
		n, err := unix.Read(fd, buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			break
		}
		ParseRawData(buffer[:n], linkType)
	}
}
