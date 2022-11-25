package socks5

import (
	"errors"
	"fmt"
)

var ErrorCouldNotConnectToProxy error = errors.New("could not connect to proxy")
var ErrorAuthError error = errors.New("auth error occurred")
var ErrorNoAuthTypeMatch error = errors.New("no acceptable methods")
var ErrorNoUdpAssoc error = errors.New("udp associate error")
var ErrorReplyDidNotSucceed error = errors.New("reply did not succeed")
var ErrorRelayConnectionFailed error = errors.New("relay connection failed to proxy")
var ErrorRelayWriteFailed error = errors.New("could not write message to relay connection")
var ErrorNoEphemeralPort error = errors.New("could not get an ephemeral port")

func mergeErrors(errs ...error) error {
	errorString := ""
	for _, err := range errs {
		errorString += fmt.Sprintf("%s\n", err.Error())
	}

	return fmt.Errorf(errorString)
}
