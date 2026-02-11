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

// tunDev is a singleton TUN device shared across all TUNPacketConn instances.
// Only one TUN device is created per process. Incoming packets are dispatched
// to the correct TUNPacketConn based on TCP destination port.
type tunDev struct {
	file    *os.File
	name    string
	localIP net.IP

	mu    sync.RWMutex
	ports map[int]chan tunFrame // port -> read channel

	ctx    context.Context
	cancel context.CancelFunc
}

var (
	tunGlobalMu sync.Mutex
	tunGlobal   *tunDev
	tunRefCount int
	tunPortSeq  uint32 // atomic counter for unique port allocation
)

// acquireTUN returns the shared TUN device, creating it on first call.
func acquireTUN(cfg *conf.Network) (*tunDev, error) {
	tunGlobalMu.Lock()
	defer tunGlobalMu.Unlock()

	if tunGlobal != nil {
		tunRefCount++
		return tunGlobal, nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	tunFile, tunName, err := createTUN("paqet0")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	flog.Infof("tun transport: created TUN device %s", tunName)

	var localIP net.IP
	if cfg.IPv4.Addr != nil {
		localIP = cfg.IPv4.Addr.IP
	} else if cfg.IPv6.Addr != nil {
		localIP = cfg.IPv6.Addr.IP
	}

	if err := configureTUN(tunName, localIP); err != nil {
		tunFile.Close()
		cancel()
		return nil, fmt.Errorf("failed to configure TUN device: %w", err)
	}

	dev := &tunDev{
		file:    tunFile,
		name:    tunName,
		localIP: localIP,
		ports:   make(map[int]chan tunFrame),
		ctx:     ctx,
		cancel:  cancel,
	}

	go dev.readLoop()

	tunGlobal = dev
	tunRefCount = 1
	return dev, nil
}

// releaseTUN decrements the refcount; when zero the device is closed.
func releaseTUN() {
	tunGlobalMu.Lock()
	defer tunGlobalMu.Unlock()

	tunRefCount--
	if tunRefCount <= 0 && tunGlobal != nil {
		tunGlobal.cancel()
		tunGlobal.file.Close()
		tunGlobal = nil
		tunRefCount = 0
	}
}

// registerPort adds a read channel for the given port. Returns the channel.
func (d *tunDev) registerPort(port int) chan tunFrame {
	ch := make(chan tunFrame, 256)
	d.mu.Lock()
	d.ports[port] = ch
	d.mu.Unlock()
	return ch
}

// unregisterPort removes the read channel for the given port.
func (d *tunDev) unregisterPort(port int) {
	d.mu.Lock()
	delete(d.ports, port)
	d.mu.Unlock()
}

// readLoop reads IP packets from the TUN device and dispatches them.
func (d *tunDev) readLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		n, err := d.file.Read(buf)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			flog.Debugf("tun transport: read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		data := buf[:n]

		var payload []byte
		var addr *net.UDPAddr
		var dstPort int

		if data[0]>>4 == 4 {
			payload, addr, dstPort = parseTUNIPv4(data)
		} else if data[0]>>4 == 6 {
			payload, addr, dstPort = parseTUNIPv6(data)
		}

		if payload == nil || len(payload) == 0 {
			continue
		}

		d.mu.RLock()
		ch, ok := d.ports[dstPort]
		d.mu.RUnlock()
		if !ok {
			continue
		}

		select {
		case ch <- tunFrame{data: append([]byte(nil), payload...), addr: addr}:
		case <-d.ctx.Done():
			return
		default:
			// Drop if channel full
		}
	}
}

// parseTUNIPv4 parses an IPv4 packet, returning payload, source addr, and TCP dst port.
func parseTUNIPv4(data []byte) ([]byte, *net.UDPAddr, int) {
	p := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
	addr := &net.UDPAddr{}

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr, 0
	}
	ipv4, ok := netLayer.(*layers.IPv4)
	if !ok {
		return nil, addr, 0
	}
	addr.IP = ipv4.SrcIP

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr, 0
	}
	tcp, ok := trLayer.(*layers.TCP)
	if !ok {
		return nil, addr, 0
	}
	addr.Port = int(tcp.SrcPort)

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr, 0
	}

	return appLayer.Payload(), addr, int(tcp.DstPort)
}

// parseTUNIPv6 parses an IPv6 packet, returning payload, source addr, and TCP dst port.
func parseTUNIPv6(data []byte) ([]byte, *net.UDPAddr, int) {
	p := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
	addr := &net.UDPAddr{}

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr, 0
	}
	ipv6, ok := netLayer.(*layers.IPv6)
	if !ok {
		return nil, addr, 0
	}
	addr.IP = ipv6.SrcIP

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr, 0
	}
	tcp, ok := trLayer.(*layers.TCP)
	if !ok {
		return nil, addr, 0
	}
	addr.Port = int(tcp.SrcPort)

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr, 0
	}

	return appLayer.Payload(), addr, int(tcp.DstPort)
}

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
	dev       *tunDev
	localIP   net.IP
	localPort int
	srcPort   uint16

	// TCP options (same approach as pcap SendHandle)
	synOptions []layers.TCPOption
	ackOptions []layers.TCPOption
	time_      uint32
	tsCounter  uint32
	tcpF       TCPF

	// Evasion
	evasionOn   bool
	entropyMgr  *evasion.EntropyManager
	probeResist *evasion.ProbeResistance
	tcpFP       *evasion.TCPFingerprint
	firstSend   sync.Map
	firstRecv   sync.Map

	// Read channel (registered in the shared tunDev)
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
	dev, err := acquireTUN(cfg)
	if err != nil {
		return nil, fmt.Errorf("tun transport: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	var localPort int
	if cfg.IPv4.Addr != nil {
		localPort = cfg.IPv4.Addr.Port
	} else if cfg.IPv6.Addr != nil {
		localPort = cfg.IPv6.Addr.Port
	}
	if localPort == 0 {
		seq := atomic.AddUint32(&tunPortSeq, 1)
		localPort = 32768 + int(seq)
	}

	readCh := dev.registerPort(localPort)

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
		dev:        dev,
		localIP:    dev.localIP,
		localPort:  localPort,
		srcPort:    uint16(localPort),
		synOptions: synOptions,
		ackOptions: ackOptions,
		time_:      uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		tcpF: TCPF{
			tcpF:       iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF},
			clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF]),
		},
		readCh: readCh,
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

	return tc, nil
}

func (tc *TUNPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := tc.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	for {
		select {
		case <-tc.ctx.Done():
			return 0, nil, tc.ctx.Err()
		case <-deadline:
			return 0, nil, os.ErrDeadlineExceeded
		case frame := <-tc.readCh:
			payload := frame.data
			addr := frame.addr

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

			n := copy(data, payload)
			return n, addr, nil
		}
	}
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

	if _, err := tc.dev.file.Write(buf.Bytes()); err != nil {
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

func (tc *TUNPacketConn) Close() error {
	tc.cancel()
	tc.dev.unregisterPort(tc.localPort)
	releaseTUN()
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
