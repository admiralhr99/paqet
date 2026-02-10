package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/evasion"
	"paqet/internal/flog"
	"runtime"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle

	// Evasion fields
	evasionOn   bool
	entropyMgr  *evasion.EntropyManager
	probeResist *evasion.ProbeResistance
	firstPacket sync.Map // tracks first packet per source "ip:port"
}

func NewRecvHandle(cfg *conf.Network, evCfg *conf.Evasion) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	rh := &RecvHandle{handle: handle}

	// Initialize evasion if enabled
	if evCfg != nil && evCfg.Enabled() {
		rh.evasionOn = true
		rh.entropyMgr = evasion.NewEntropyManager(evCfg.EntropyMode, evCfg.SNI)
		rh.probeResist = evasion.NewProbeResistance(evCfg.AuthSecret, evCfg.FallbackURL)
		flog.Infof("evasion receive handler enabled: mode=%s", evCfg.EntropyMode)
	}

	return rh, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	addr := &net.UDPAddr{}
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr, nil
	}
	switch netLayer.LayerType() {
	case layers.LayerTypeIPv4:
		addr.IP = netLayer.(*layers.IPv4).SrcIP
	case layers.LayerTypeIPv6:
		addr.IP = netLayer.(*layers.IPv6).SrcIP
	}

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr, nil
	}
	switch trLayer.LayerType() {
	case layers.LayerTypeTCP:
		addr.Port = int(trLayer.(*layers.TCP).SrcPort)
	case layers.LayerTypeUDP:
		addr.Port = int(trLayer.(*layers.UDP).SrcPort)
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr, nil
	}

	payload := appLayer.Payload()

	// === Evasion: first packet unwrapping (entropy + auth validation) ===
	if h.evasionOn && len(payload) > 0 && h.entropyMgr != nil && h.probeResist != nil {
		addrKey := addr.String()
		if _, loaded := h.firstPacket.LoadOrStore(addrKey, true); !loaded {
			// Step 1: Unwrap TLS ClientHello / HTTP prefix
			unwrapped, err := h.entropyMgr.UnwrapFirstPacket(payload)
			if err != nil {
				flog.Debugf("evasion: entropy unwrap failed from %s: %v", addrKey, err)
				h.firstPacket.Delete(addrKey) // allow retry
				return nil, addr, nil         // drop packet
			}

			// Step 2: Extract and validate HMAC auth token
			kcpPayload, valid, err := h.probeResist.ExtractAndValidate(unwrapped)
			if err != nil || !valid {
				flog.Debugf("evasion: auth failed from %s (valid=%v, err=%v)", addrKey, valid, err)
				h.firstPacket.Delete(addrKey) // allow retry
				return nil, addr, nil         // drop packet
			}

			flog.Debugf("evasion: first packet unwrapped from %s (%d -> %d bytes)", addrKey, len(payload), len(kcpPayload))
			return kcpPayload, addr, nil
		}
	}

	return payload, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
