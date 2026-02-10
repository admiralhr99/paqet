package conf

import (
	"fmt"
	"net"
	"runtime"
	"slices"
)

type Addr struct {
	Addr_      string           `yaml:"addr"`
	RouterMac_ string           `yaml:"router_mac"`
	Addr       *net.UDPAddr     `yaml:"-"`
	Router     net.HardwareAddr `yaml:"-"`
}

// NFQueue holds NFQUEUE-specific configuration.
type NFQueue struct {
	OutQueue uint16 `yaml:"out_queue"`
	InQueue  uint16 `yaml:"in_queue"`
}

type Network struct {
	Mode       string         `yaml:"mode"` // "pcap" (default), "tun", "tcp", "nfqueue"
	Interface_ string         `yaml:"interface"`
	GUID       string         `yaml:"guid"`
	IPv4       Addr           `yaml:"ipv4"`
	IPv6       Addr           `yaml:"ipv6"`
	PCAP       PCAP           `yaml:"pcap"`
	TCP        TCP            `yaml:"tcp"`
	NFQueue    NFQueue        `yaml:"nfqueue"`
	Interface  *net.Interface `yaml:"-"`
	Port       int            `yaml:"-"`
}

func (n *Network) setDefaults(role string) {
	if n.Mode == "" {
		n.Mode = "pcap"
	}
	n.PCAP.setDefaults(role)
	n.TCP.setDefaults()
	if n.NFQueue.OutQueue == 0 {
		n.NFQueue.OutQueue = 100
	}
	if n.NFQueue.InQueue == 0 {
		n.NFQueue.InQueue = 101
	}
}

func (n *Network) validate() []error {
	var errors []error

	validModes := []string{"pcap", "tun", "tcp", "nfqueue"}
	if !slices.Contains(validModes, n.Mode) {
		errors = append(errors, fmt.Errorf("network.mode must be one of: %v", validModes))
		return errors
	}

	// TCP and NFQUEUE modes use the kernel TCP stack — they don't need
	// interface, IP addresses, router MACs, PCAP config, or TCP flags.
	if n.Mode == "tcp" || n.Mode == "nfqueue" {
		return errors
	}

	// pcap and tun modes require interface and IP configuration
	if n.Interface_ == "" {
		errors = append(errors, fmt.Errorf("network interface is required"))
	}
	if len(n.Interface_) > 15 {
		errors = append(errors, fmt.Errorf("network interface name too long (max 15 characters): '%s'", n.Interface_))
	}
	lIface, err := net.InterfaceByName(n.Interface_)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to find network interface %s: %v", n.Interface_, err))
	}
	n.Interface = lIface

	if runtime.GOOS == "windows" && n.GUID == "" {
		errors = append(errors, fmt.Errorf("guid is required on windows"))
	}

	ipv4Configured := n.IPv4.Addr_ != ""
	ipv6Configured := n.IPv6.Addr_ != ""
	if !ipv4Configured && !ipv6Configured {
		errors = append(errors, fmt.Errorf("at least one address family (IPv4 or IPv6) must be configured"))
		return errors
	}
	if ipv4Configured {
		if n.Mode == "tun" {
			// TUN mode: validate address but router MAC is not required
			errors = append(errors, n.IPv4.validateAddr()...)
		} else {
			errors = append(errors, n.IPv4.validate()...)
		}
	}
	if ipv6Configured {
		if n.Mode == "tun" {
			errors = append(errors, n.IPv6.validateAddr()...)
		} else {
			errors = append(errors, n.IPv6.validate()...)
		}
	}
	if ipv4Configured && ipv6Configured {
		if n.IPv4.Addr != nil && n.IPv6.Addr != nil && n.IPv4.Addr.Port != n.IPv6.Addr.Port {
			errors = append(errors, fmt.Errorf("IPv4 port (%d) and IPv6 port (%d) must match when both are configured", n.IPv4.Addr.Port, n.IPv6.Addr.Port))
		}
	}
	if n.IPv4.Addr != nil {
		n.Port = n.IPv4.Addr.Port
	}
	if n.IPv6.Addr != nil {
		n.Port = n.IPv6.Addr.Port
	}

	if n.Mode == "pcap" {
		errors = append(errors, n.PCAP.validate()...)
	}
	errors = append(errors, n.TCP.validate()...)

	return errors
}

// validateAddr validates only the address (no router MAC requirement).
// Used by TUN mode where the kernel handles MAC addresses.
func (n *Addr) validateAddr() []error {
	var errors []error

	l, err := validateAddr(n.Addr_, false)
	if err != nil {
		errors = append(errors, err)
	}
	n.Addr = l

	return errors
}

func (n *Addr) validate() []error {
	var errors []error

	l, err := validateAddr(n.Addr_, false)
	if err != nil {
		errors = append(errors, err)
	}
	n.Addr = l

	if n.RouterMac_ == "" {
		errors = append(errors, fmt.Errorf("Router MAC address is required"))
	}

	hwAddr, err := net.ParseMAC(n.RouterMac_)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid Router MAC address '%s': %v", n.RouterMac_, err))
	}
	n.Router = hwAddr

	return errors
}
