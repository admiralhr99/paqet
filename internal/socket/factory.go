package socket

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
)

// ClientTCPFSetter is an optional interface for transport modes that support
// per-client TCP flag configuration (currently only pcap mode).
type ClientTCPFSetter interface {
	SetClientTCPF(addr net.Addr, f []conf.TCPF)
}

// NewPacketConn creates a net.PacketConn appropriate for the configured transport mode.
// This is the main entry point for creating transport connections.
func NewPacketConn(ctx context.Context, cfg *conf.Network, evCfg *conf.Evasion) (net.PacketConn, error) {
	switch cfg.Mode {
	case "pcap", "":
		return New(ctx, cfg, evCfg)
	case "tun":
		return NewTUNPacketConn(ctx, cfg, evCfg)
	case "tcp":
		return NewTCPPacketConn(ctx, cfg, evCfg)
	case "nfqueue":
		return NewNFQueuePacketConn(ctx, cfg, evCfg)
	default:
		return nil, fmt.Errorf("unknown transport mode: %s", cfg.Mode)
	}
}
