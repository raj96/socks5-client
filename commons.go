package socks5

import (
	"log"
	"net"
)

func CheckErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s\nError occurred: %s\n", msg, err)
	}
}

func GetEphemeralPort() (uint16, *net.TCPListener, error) {
	var ePort uint16 = 0

	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return ePort, nil, err
	}

	localAddr := lis.Addr().(*net.TCPAddr)
	ePort = localAddr.AddrPort().Port()

	return ePort, lis, nil
}
