//go:build !cgo

package socket

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
)

// New returns an error when built without CGO since pcap mode requires libpcap C bindings.
func New(_ context.Context, _ *conf.Network, _ *conf.Evasion) (net.PacketConn, error) {
	return nil, fmt.Errorf("pcap transport requires CGO (libpcap); build with CGO_ENABLED=1 or use mode: tcp/tun/nfqueue")
}
