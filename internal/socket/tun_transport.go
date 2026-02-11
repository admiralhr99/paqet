package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/evasion"
	"paqet/internal/flog"
	"paqet/internal/pkg/iterator"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TUNPacketConn uses a TUN device to send/receive IP packets.
// Unlike pcap mode which bypasses the kernel entirely, TUN mode writes
// IP-level packets into the TUN device. The kernel then routes them through
// the real interface, adding proper Ethernet headers and MAC addresses.
//
// This satisfies hypervisors that validate MAC/IP spoofing (OpenStack anti-spoofing)
// because the kernel's routing stack handles Ethernet framing.
//
// Packets still have manually crafted IP+TCP headers (same as pcap mode
// minus the Ethernet layer), so all evasion modules work.
type TUNPacketConn struct {
	tunFile   *os.File // TUN device file descriptor
	tunName   string   // e.g., "paqet0"
	localIP   net.IP
	localPort int
	cfg       *conf.Network

	// TCP options (same approach as pcap SendHandle)
	synOptions []layers.TCPOption
	ackOptions []layers.TCPOption
	time_      uint32
	tsCounter  uint32
	srcPort    uint16
	tcpF       TCPF

	// Evasion
	evasionOn   bool
	entropyMgr  *evasion.EntropyManager
	probeResist *evasion.ProbeResistance
	tcpFP       *evasion.TCPFingerprint
	firstSend   sync.Map
	firstRecv   sync.Map

	// Read channel
	readCh chan tunFrame

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
}

type tunFrame struct {
	data []byte
	addr *net.UDPAddr
}

// NewTUNPacketConn creates a TUN-device based PacketConn.
func NewTUNPacketConn(ctx context.Context, cfg *conf.Network, evCfg *conf.Evasion) (*TUNPacketConn, error) {
	ctx, cancel := context.WithCancel(ctx)

	tunFile, tunName, err := createTUN("paqet0")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tun transport: failed to create TUN device: %w", err)
	}
	flog.Infof("tun transport: created TUN device %s", tunName)

	// Configure the TUN device with the local IP
	var localIP net.IP
	var localPort int
	if cfg.IPv4.Addr != nil {
		localIP = cfg.IPv4.Addr.IP
		localPort = cfg.IPv4.Addr.Port
	} else if cfg.IPv6.Addr != nil {
		localIP = cfg.IPv6.Addr.IP
		localPort = cfg.IPv6.Addr.Port
	}

	if err := configureTUN(tunName, localIP); err != nil {
		tunFile.Close()
		cancel()
		return nil, fmt.Errorf("tun transport: failed to configure TUN device: %w", err)
	}

	if localPort == 0 {
		localPort = 32768 + int(time.Now().UnixNano()%32768)
	}

	synOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	}

	ackOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
	}

	tc := &TUNPacketConn{
		tunFile:    tunFile,
		tunName:    tunName,
		localIP:    localIP,
		localPort:  localPort,
		cfg:        cfg,
		synOptions: synOptions,
		ackOptions: ackOptions,
		time_:      uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		srcPort:    uint16(localPort),
		tcpF: TCPF{
			tcpF:       iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF},
			clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF]),
		},
		readCh: make(chan tunFrame, 256),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize evasion if enabled
	if evCfg != nil && evCfg.Enabled() {
		tc.evasionOn = true
		tc.entropyMgr = evasion.NewEntropyManager(evCfg.EntropyMode, evCfg.SNI)
		tc.probeResist = evasion.NewProbeResistance(evCfg.AuthSecret, evCfg.FallbackURL)
		tc.tcpFP = evasion.NewTCPFingerprint()
		flog.Infof("tun transport: evasion enabled: mode=%s sni=%s", evCfg.EntropyMode, evCfg.SNI)
	}

	// Start reading from TUN device
	go tc.readLoop()

	return tc, nil
}

// readLoop continuously reads IP packets from the TUN device.
func (tc *TUNPacketConn) readLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
		}

		n, err := tc.tunFile.Read(buf)
		if err != nil {
			if tc.ctx.Err() != nil {
				return
			}
			flog.Debugf("tun transport: read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		data := buf[:n]
		addr := &net.UDPAddr{}

		// Parse IP packet to extract source address and TCP payload
		var payload []byte
		if data[0]>>4 == 4 {
			payload, addr = tc.parseIPv4Packet(data)
		} else if data[0]>>4 == 6 {
			payload, addr = tc.parseIPv6Packet(data)
		}

		if payload == nil || len(payload) == 0 {
			continue
		}

		// Evasion: unwrap first packet
		if tc.evasionOn && tc.entropyMgr != nil && tc.probeResist != nil {
			addrKey := addr.String()
			if _, loaded := tc.firstRecv.LoadOrStore(addrKey, true); !loaded {
				unwrapped, err := tc.entropyMgr.UnwrapFirstPacket(payload)
				if err != nil {
					flog.Debugf("tun transport: entropy unwrap failed from %s: %v", addrKey, err)
					tc.firstRecv.Delete(addrKey)
					continue
				}
				kcpPayload, valid, err := tc.probeResist.ExtractAndValidate(unwrapped)
				if err != nil || !valid {
					flog.Debugf("tun transport: auth failed from %s (valid=%v, err=%v)", addrKey, valid, err)
					tc.firstRecv.Delete(addrKey)
					continue
				}
				flog.Debugf("tun transport: first packet unwrapped from %s (%d -> %d bytes)", addrKey, len(payload), len(kcpPayload))
				payload = kcpPayload
			}
		}

		select {
		case tc.readCh <- tunFrame{data: append([]byte(nil), payload...), addr: addr}:
		case <-tc.ctx.Done():
			return
		}
	}
}

func (tc *TUNPacketConn) parseIPv4Packet(data []byte) ([]byte, *net.UDPAddr) {
	p := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
	addr := &net.UDPAddr{}

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr
	}
	ipv4, ok := netLayer.(*layers.IPv4)
	if !ok {
		return nil, addr
	}
	addr.IP = ipv4.SrcIP

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr
	}
	tcp, ok := trLayer.(*layers.TCP)
	if !ok {
		return nil, addr
	}
	addr.Port = int(tcp.SrcPort)

	// Only accept packets to our port
	if int(tcp.DstPort) != tc.localPort {
		return nil, addr
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr
	}

	return appLayer.Payload(), addr
}

func (tc *TUNPacketConn) parseIPv6Packet(data []byte) ([]byte, *net.UDPAddr) {
	p := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
	addr := &net.UDPAddr{}

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr
	}
	ipv6, ok := netLayer.(*layers.IPv6)
	if !ok {
		return nil, addr
	}
	addr.IP = ipv6.SrcIP

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr
	}
	tcp, ok := trLayer.(*layers.TCP)
	if !ok {
		return nil, addr
	}
	addr.Port = int(tcp.SrcPort)

	if int(tcp.DstPort) != tc.localPort {
		return nil, addr
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr
	}

	return appLayer.Payload(), addr
}

func (tc *TUNPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := tc.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-tc.ctx.Done():
		return 0, tc.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	payload := data

	// Evasion: wrap first packet
	if tc.evasionOn && tc.entropyMgr != nil && tc.probeResist != nil {
		addrKey := daddr.String()
		if _, loaded := tc.firstSend.LoadOrStore(addrKey, true); !loaded {
			authed, err := tc.probeResist.PrependAuthToken(payload)
			if err != nil {
				flog.Errorf("tun transport: auth token failed: %v", err)
			} else {
				wrapped, err := tc.entropyMgr.WrapFirstPacket(authed)
				if err != nil {
					flog.Errorf("tun transport: entropy wrap failed: %v", err)
					payload = authed
				} else {
					payload = wrapped
					flog.Debugf("tun transport: first packet wrapped (%d bytes) for %s", len(payload), addrKey)
				}
			}
		}
	}

	// Build IP+TCP packet (no Ethernet header — TUN operates at IP level)
	dstIP := daddr.IP
	dstPort := uint16(daddr.Port)

	f := tc.getClientTCPF(dstIP, dstPort)
	tcpLayer := tc.buildTCPHeader(dstPort, f)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := tc.buildIPv4Header(dstIP)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
	} else {
		ip := tc.buildIPv6Header(dstIP)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return 0, fmt.Errorf("tun transport: serialize error: %w", err)
	}

	if _, err := tc.tunFile.Write(buf.Bytes()); err != nil {
		return 0, fmt.Errorf("tun transport: write error: %w", err)
	}

	return len(data), nil
}

func (tc *TUNPacketConn) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    tc.localIP,
		DstIP:    dstIP,
	}
	if tc.evasionOn && tc.tcpFP != nil {
		tc.tcpFP.NormalizeIPv4(ip)
	}
	return ip
}

func (tc *TUNPacketConn) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      tc.localIP,
		DstIP:      dstIP,
	}
	if tc.evasionOn && tc.tcpFP != nil {
		tc.tcpFP.NormalizeIPv6(ip)
	}
	return ip
}

func (tc *TUNPacketConn) buildTCPHeader(dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(tc.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&tc.tsCounter, 1)
	tsVal := tc.time_ + (counter >> 3)
	if f.SYN {
		binary.BigEndian.PutUint32(tc.synOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tc.synOptions[2].OptionData[4:8], 0)
		tcp.Options = tc.synOptions
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(tc.ackOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tc.ackOptions[2].OptionData[4:8], tsEcr)
		tcp.Options = tc.ackOptions
		seq := tc.time_ + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (tc *TUNPacketConn) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	return tc.tcpF.getClientTCPF(dstIP, dstPort)
}

func (tc *TUNPacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	tc.tcpF.setClientTCPF(a.IP, uint16(a.Port), f)
}

func (tc *TUNPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := tc.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-tc.ctx.Done():
		return 0, nil, tc.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	case frame := <-tc.readCh:
		n := copy(data, frame.data)
		return n, frame.addr, nil
	}
}

func (tc *TUNPacketConn) Close() error {
	tc.cancel()
	if tc.tunFile != nil {
		tc.tunFile.Close()
	}
	return nil
}

func (tc *TUNPacketConn) LocalAddr() net.Addr {
	return nil
}

func (tc *TUNPacketConn) SetDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	tc.writeDeadline.Store(t)
	return nil
}

func (tc *TUNPacketConn) SetReadDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	return nil
}

func (tc *TUNPacketConn) SetWriteDeadline(t time.Time) error {
	tc.writeDeadline.Store(t)
	return nil
}
