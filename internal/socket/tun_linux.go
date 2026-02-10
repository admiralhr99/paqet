//go:build linux

package socket

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice  = "/dev/net/tun"
	tunIFF_TUN = 0x0001
	tunIFF_NO_PI = 0x1000 // no packet info header
)

// ifReq is the ioctl request struct for creating TUN interfaces.
// Matches struct ifreq from linux/if.h.
type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_pad  [22]byte // padding to match sizeof(struct ifreq)
}

// createTUN opens /dev/net/tun and creates a TUN interface.
// Returns the file descriptor, the actual interface name, and any error.
func createTUN(name string) (*os.File, string, error) {
	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	var req ifReq
	req.Flags = tunIFF_TUN | tunIFF_NO_PI
	copy(req.Name[:], name)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	// Extract the actual interface name (kernel may have appended a number)
	actualName := string(req.Name[:])
	for i, b := range req.Name {
		if b == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}

	file := os.NewFile(uintptr(fd), tunDevice)
	return file, actualName, nil
}

// configureTUN sets up the TUN interface with an IP address and brings it up.
func configureTUN(tunName string, localIP net.IP) error {
	// Assign IP address
	var cidr string
	if localIP.To4() != nil {
		cidr = localIP.String() + "/32"
	} else {
		cidr = localIP.String() + "/128"
	}

	if err := exec.Command("ip", "addr", "add", cidr, "dev", tunName).Run(); err != nil {
		return fmt.Errorf("failed to add address %s to %s: %w", cidr, tunName, err)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", tunName, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up %s: %w", tunName, err)
	}

	// Set MTU (slightly smaller to account for TUN overhead)
	if err := exec.Command("ip", "link", "set", tunName, "mtu", "1400").Run(); err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tunName, err)
	}

	return nil
}
