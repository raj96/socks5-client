package socks5

import (
	"net"
)

type Socks5Client struct {
	ProxyConnection    *net.TCPConn
	RelayConnection    *net.UDPConn
	DestinationAddress *net.TCPAddr
	bindAddr           *net.IP
	bindPort           uint16
	UdpAssociatedPort  uint16
	addressType        byte
	ephemeralListener  *net.TCPListener
}

func CreateNewSocks5Client(proxyAddress *net.TCPAddr, authType byte) (*Socks5Client, error) {
	proxyConn, err := net.DialTCP("tcp", nil, proxyAddress)
	if err != nil {
		return nil, mergeErrors(err, ErrorCouldNotConnectToProxy)
	}

	// Check for authentication methods
	authNegMsg := []byte{
		VERSION,
		// Number of methods
		0x01,
		authType}
	_, err = proxyConn.Write(authNegMsg)
	if err != nil {
		return nil, mergeErrors(err, ErrorAuthError)
	}

	authNegMsg = make([]byte, 2)
	_, err = proxyConn.Read(authNegMsg)
	if err != nil {
		return nil, mergeErrors(err, ErrorAuthError)
	}

	if authNegMsg[1] == AUTH_TYPE_NO_MATCH {
		return nil, ErrorNoAuthTypeMatch
	}

	return &Socks5Client{
		ProxyConnection: proxyConn,
	}, nil
}

func (client *Socks5Client) ConnectTCP(destinationAddress *net.TCPAddr) {
	client.DestinationAddress = destinationAddress
	var connectMsg []byte

	ipv4DestinationAddress := client.DestinationAddress.IP.To4()
	ipv6DestinationAddress := client.DestinationAddress.IP.To16()

	if ipv4DestinationAddress != nil {
		connectMsg = []byte{
			VERSION,
			CMD_CONNECT,
			RESERVED,
			ATYP_IPV4,
			ipv4DestinationAddress[0],
			ipv4DestinationAddress[1],
			ipv4DestinationAddress[2],
			ipv4DestinationAddress[3],
			byte(client.DestinationAddress.Port >> 8),
			byte(client.DestinationAddress.Port & 0xFF),
		}
	} else if ipv6DestinationAddress != nil {
		connectMsg = []byte{
			VERSION,
			CMD_CONNECT,
			RESERVED,
			ATYP_IPV6,
			ipv6DestinationAddress[0],
			ipv6DestinationAddress[1],
			ipv6DestinationAddress[2],
			ipv6DestinationAddress[3],
			ipv6DestinationAddress[4],
			ipv6DestinationAddress[5],
			ipv6DestinationAddress[6],
			ipv6DestinationAddress[7],
			ipv6DestinationAddress[8],
			ipv6DestinationAddress[9],
			ipv6DestinationAddress[10],
			ipv6DestinationAddress[11],
			ipv6DestinationAddress[12],
			ipv6DestinationAddress[13],
			ipv6DestinationAddress[14],
			ipv6DestinationAddress[15],
			byte(client.DestinationAddress.Port >> 8),
			byte(client.DestinationAddress.Port & 0xFF),
		}

	}

	_, err := client.ProxyConnection.Write(connectMsg)
	CheckErr(err, "Could not send Connect packet")

	r_connectMsg := make([]byte, 1024)
	_, err = client.ProxyConnection.Read(r_connectMsg)
	CheckErr(err, "Could not read the reply to Connect packet")

	// TODO
}

func (client *Socks5Client) sendUDPAssociate() error {
	ephemeralPort, ephemeralListener, err := GetEphemeralPort()
	if err != nil {
		return mergeErrors(err, ErrorNoEphemeralPort)
	}
	client.UdpAssociatedPort = ephemeralPort
	client.ephemeralListener = ephemeralListener

	connectMsg := []byte{
		VERSION,
		CMD_UDP_ASSOCIATE,
		RESERVED,
		ATYP_IPV4,
		//IP Address
		0x00,
		0x00,
		0x00,
		0x00,
		//Port number
		byte(ephemeralPort >> 8),
		byte(ephemeralPort & 0xFF),
	}

	_, err = client.ProxyConnection.Write(connectMsg)
	if err != nil {
		return mergeErrors(err, ErrorNoUdpAssoc)
	}

	r_connectMsg := make([]byte, 1024)
	_, err = client.ProxyConnection.Read(r_connectMsg)
	if err != nil {
		return mergeErrors(err, ErrorNoUdpAssoc)
	}

	if r_connectMsg[1] != REPLY_SUCCEEDED {
		return mergeErrors(err, ErrorReplyDidNotSucceed)
	}

	if r_connectMsg[3] == ATYP_IPV4 {
		client.bindAddr = &net.IP{
			r_connectMsg[4],
			r_connectMsg[5],
			r_connectMsg[6],
			r_connectMsg[7],
		}
		client.bindPort = uint16(uint16(r_connectMsg[8])<<8 | uint16(r_connectMsg[9]))
	}

	if client.ephemeralListener != nil {
		client.ephemeralListener.Close()
	}
	relayConn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(ephemeralPort)}, &net.UDPAddr{IP: *client.bindAddr, Port: int(client.bindPort)})
	if err != nil {
		return mergeErrors(err, ErrorRelayConnectionFailed)
	}
	client.RelayConnection = relayConn

	return nil
}

func (client *Socks5Client) SendUDPTo(destinationAddress *net.UDPAddr, message string) error {
	client.DestinationAddress = (*net.TCPAddr)(destinationAddress)
	if client.bindAddr == nil || client.bindPort == 0 || client.UdpAssociatedPort == 0 {
		err := client.sendUDPAssociate()
		if err != nil {
			return mergeErrors(err, ErrorNoUdpAssoc)
		}
	}

	var udpAssociatedPacket []byte

	ipv4DestinationAddr := destinationAddress.IP.To4()
	ipv6DestinationAddr := destinationAddress.IP.To16()

	if ipv4DestinationAddr != nil {
		client.addressType = ATYP_IPV4
		udpAssociatedPacket = []byte{
			RESERVED,
			RESERVED,
			BLANK_FRAG,
			ATYP_IPV4,
			ipv4DestinationAddr[0],
			ipv4DestinationAddr[1],
			ipv4DestinationAddr[2],
			ipv4DestinationAddr[3],
			byte(client.DestinationAddress.Port >> 8),
			byte(client.DestinationAddress.Port & 0xFF),
		}
	} else if ipv6DestinationAddr != nil {
		client.addressType = ATYP_IPV6
		udpAssociatedPacket = []byte{
			RESERVED,
			RESERVED,
			BLANK_FRAG,
			ATYP_IPV6,
			ipv6DestinationAddr[0],
			ipv6DestinationAddr[1],
			ipv6DestinationAddr[2],
			ipv6DestinationAddr[3],
			ipv6DestinationAddr[4],
			ipv6DestinationAddr[5],
			ipv6DestinationAddr[6],
			ipv6DestinationAddr[7],
			ipv6DestinationAddr[8],
			ipv6DestinationAddr[9],
			ipv6DestinationAddr[10],
			ipv6DestinationAddr[11],
			ipv6DestinationAddr[12],
			ipv6DestinationAddr[13],
			ipv6DestinationAddr[14],
			ipv6DestinationAddr[15],
			byte(client.DestinationAddress.Port >> 8),
			byte(client.DestinationAddress.Port & 0xFF),
		}
	}

	udpAssociatedPacket = append(udpAssociatedPacket, []byte(message)...)
	_, err := client.RelayConnection.Write(udpAssociatedPacket)
	if err != nil {
		return mergeErrors(err, ErrorRelayWriteFailed)
	}

	return nil
}

func (client *Socks5Client) RecvUDP(msgBufferSize int) ([]byte, error) {
	var socksHeaderLength int

	if client.addressType == ATYP_IPV4 {
		socksHeaderLength = 10
	} else if client.addressType == ATYP_IPV6 {
		socksHeaderLength = 22
	}

	msgBuffer := make([]byte, socksHeaderLength+msgBufferSize)

	_, _, err := client.RelayConnection.ReadFromUDP(msgBuffer)
	if err != nil {
		return []byte{}, err
	}

	return msgBuffer[socksHeaderLength:], nil
}

func (client *Socks5Client) Close() {
	if client.RelayConnection != nil {
		client.RelayConnection.Close()
	}
	if client.ProxyConnection != nil {
		client.ProxyConnection.Close()
	}
}
