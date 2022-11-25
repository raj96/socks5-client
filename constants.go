package socks5

const (
	VERSION    byte = 0x05
	RESERVED   byte = 0x00
	BLANK_FRAG byte = 0x00
)

const (
	AUTH_TYPE_NO_AUTH   byte = 0x00
	AUTH_TYPE_GSSAPI    byte = 0x01
	AUTH_TYPE_USER_NAME byte = 0x02
	AUTH_TYPE_NO_MATCH  byte = 0xFF
)

const (
	CMD_CONNECT       byte = 0x01
	CMD_BIND          byte = 0x02
	CMD_UDP_ASSOCIATE byte = 0x03
)

const (
	ATYP_IPV4        byte = 0x01
	ATYP_DOMAIN_NAME byte = 0x03
	ATYP_IPV6        byte = 0x04
)

const (
	REPLY_SUCCEEDED               byte = 0x00
	REPLY_GEN_SOCKS_FAILURE       byte = 0x01
	REPLY_CONN_NOT_ALLOWED        byte = 0x02
	REPLY_NETWORK_UNREACHABLE     byte = 0x03
	REPLY_HOST_UNREACHABLE        byte = 0x04
	REPLY_CONN_REFUSED            byte = 0x05
	REPLY_TTL_EXPIRED             byte = 0x06
	REPLY_CMD_NOT_SUPPORTED       byte = 0x07
	REPLY_ADDR_TYPE_NOT_SUPPORTED byte = 0x08
)
