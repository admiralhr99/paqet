//go:build !linux

package socket

import (
	"fmt"
	"net"
	"os"
)

func createTUN(name string) (*os.File, string, error) {
	return nil, "", fmt.Errorf("TUN transport is only supported on Linux")
}

func configureTUN(tunName string, localIP net.IP) error {
	return fmt.Errorf("TUN transport is only supported on Linux")
}
