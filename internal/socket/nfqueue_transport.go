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
	"sync"
	"sync/atomic"
	"time"
)

// NFQueuePacketConn combines a real kernel TCP connection with NFQUEUE
// packet interception. The kernel handles the TCP 3-way handshake and
// state machine (satisfying hypervisor checks), while NFQUEUE captures
// packets after kernel processing but before they leave the wire,
// allowing paqet to modify TCP payloads and headers for DPI evasion.
//
// Architecture:
//   Write path: KCP → TCP socket → kernel builds packet → NFQUEUE captures →
//               paqet modifies (evasion) → release to wire
//   Read path:  wire → NFQUEUE captures incoming → paqet unwraps (evasion) →
//               release to kernel → TCP socket → KCP
//
// This gives the best of both worlds: real TCP state + full packet control.
// Requires root/CAP_NET_ADMIN and iptables rules to direct packets to the queue.
type NFQueuePacketConn struct {
	conn       net.Conn     // Real kernel TCP connection
	listener   net.Listener // Server mode listener
	remoteAddr *net.UDPAddr
	isServer   bool

	// NFQUEUE configuration
	outQueue uint16
	inQueue  uint16

	// NFQUEUE handles (Linux-specific)
	outNfq nfqHandle
	inNfq  nfqHandle

	// Active connections (server mode)
	serverMu    sync.RWMutex
	serverConns map[string]*nfqPeer

	// Evasion
	evasionOn   bool
	entropyMgr  *evasion.EntropyManager
	probeResist *evasion.ProbeResistance
	tcpFP       *evasion.TCPFingerprint
	firstSend   sync.Map
	firstRecv   sync.Map

	// Read channel for KCP payloads extracted from intercepted packets
	readCh chan nfqFrame

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
}

type nfqPeer struct {
	conn net.Conn
	addr *net.UDPAddr
}

type nfqFrame struct {
	data []byte
	addr *net.UDPAddr
}

// nfqHandle is an opaque handle to an NFQUEUE instance (platform-specific).
type nfqHandle interface {
	Close() error
}

// nfqPacketHandler is called for each intercepted packet.
// Returns (possibly modified packet data, accept bool).
type nfqPacketHandler func(pktData []byte) ([]byte, bool)

// NewNFQueuePacketConn creates an NFQUEUE-based PacketConn.
func NewNFQueuePacketConn(ctx context.Context, cfg *conf.Network, evCfg *conf.Evasion) (*NFQueuePacketConn, error) {
	ctx, cancel := context.WithCancel(ctx)

	nc := &NFQueuePacketConn{
		isServer:    cfg.Port > 0,
		outQueue:    cfg.NFQueue.OutQueue,
		inQueue:     cfg.NFQueue.InQueue,
		serverConns: make(map[string]*nfqPeer),
		readCh:      make(chan nfqFrame, 256),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize evasion if enabled
	if evCfg != nil && evCfg.Enabled() {
		nc.evasionOn = true
		nc.entropyMgr = evasion.NewEntropyManager(evCfg.EntropyMode, evCfg.SNI)
		nc.probeResist = evasion.NewProbeResistance(evCfg.AuthSecret, evCfg.FallbackURL)
		nc.tcpFP = evasion.NewTCPFingerprint()
		flog.Infof("nfqueue transport: evasion enabled: mode=%s sni=%s", evCfg.EntropyMode, evCfg.SNI)
	}

	// Start NFQUEUE handlers
	outNfq, err := startNFQueue(ctx, nc.outQueue, nc.handleOutgoing)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("nfqueue transport: failed to start outgoing queue %d: %w", nc.outQueue, err)
	}
	nc.outNfq = outNfq

	inNfq, err := startNFQueue(ctx, nc.inQueue, nc.handleIncoming)
	if err != nil {
		outNfq.Close()
		cancel()
		return nil, fmt.Errorf("nfqueue transport: failed to start incoming queue %d: %w", nc.inQueue, err)
	}
	nc.inNfq = inNfq

	flog.Infof("nfqueue transport: queues started (out=%d, in=%d)", nc.outQueue, nc.inQueue)

	if nc.isServer {
		listenAddr := fmt.Sprintf(":%d", cfg.Port)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("nfqueue transport: failed to listen on %s: %w", listenAddr, err)
		}
		nc.listener = ln
		flog.Infof("nfqueue transport: server listening on %s", listenAddr)

		go nc.acceptLoop()
	}

	return nc, nil
}

// handleOutgoing processes outgoing packets captured by NFQUEUE.
// It applies evasion wrapping to first packets and TCP fingerprint normalization.
func (nc *NFQueuePacketConn) handleOutgoing(pktData []byte) ([]byte, bool) {
	if !nc.evasionOn {
		return pktData, true // accept unmodified
	}

	// Parse the IP packet to find TCP payload
	ipPayload, tcpPayloadOffset, srcAddr := parseIPTCPPacket(pktData)
	if ipPayload == nil || tcpPayloadOffset <= 0 {
		return pktData, true // not a TCP packet, accept as-is
	}

	tcpPayload := pktData[tcpPayloadOffset:]
	if len(tcpPayload) == 0 {
		return pktData, true // no payload (SYN/ACK/etc.), accept as-is
	}

	_ = srcAddr

	// Apply TCP fingerprint normalization to the packet headers
	if nc.tcpFP != nil {
		modified := normalizeTCPHeaders(pktData, nc.tcpFP)
		if modified != nil {
			pktData = modified
		}
	}

	return pktData, true // accept (possibly modified)
}

// handleIncoming processes incoming packets captured by NFQUEUE.
// It extracts TCP payloads and puts them in the read channel after evasion unwrapping.
func (nc *NFQueuePacketConn) handleIncoming(pktData []byte) ([]byte, bool) {
	// Parse the IP packet
	_, tcpPayloadOffset, srcAddr := parseIPTCPPacket(pktData)
	if tcpPayloadOffset <= 0 || srcAddr == nil {
		return pktData, true
	}

	tcpPayload := pktData[tcpPayloadOffset:]
	if len(tcpPayload) == 0 {
		return pktData, true // no payload, accept
	}

	payload := make([]byte, len(tcpPayload))
	copy(payload, tcpPayload)

	// Evasion: unwrap first packet
	if nc.evasionOn && nc.entropyMgr != nil && nc.probeResist != nil {
		addrKey := srcAddr.String()
		if _, loaded := nc.firstRecv.LoadOrStore(addrKey, true); !loaded {
			unwrapped, err := nc.entropyMgr.UnwrapFirstPacket(payload)
			if err != nil {
				flog.Debugf("nfqueue transport: entropy unwrap failed from %s: %v", addrKey, err)
				nc.firstRecv.Delete(addrKey)
				return pktData, true
			}
			kcpPayload, valid, err := nc.probeResist.ExtractAndValidate(unwrapped)
			if err != nil || !valid {
				flog.Debugf("nfqueue transport: auth failed from %s (valid=%v, err=%v)", addrKey, valid, err)
				nc.firstRecv.Delete(addrKey)
				return pktData, true
			}
			flog.Debugf("nfqueue transport: first packet unwrapped from %s", addrKey)
			payload = kcpPayload
		}
	}

	select {
	case nc.readCh <- nfqFrame{data: payload, addr: srcAddr}:
	default:
		flog.Debugf("nfqueue transport: read channel full, dropping packet")
	}

	return pktData, true // accept the original packet to kernel
}

// acceptLoop accepts incoming TCP connections (server mode).
func (nc *NFQueuePacketConn) acceptLoop() {
	for {
		conn, err := nc.listener.Accept()
		if err != nil {
			select {
			case <-nc.ctx.Done():
				return
			default:
				flog.Errorf("nfqueue transport: accept error: %v", err)
				continue
			}
		}

		tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
		udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
		peer := &nfqPeer{conn: conn, addr: udpAddr}

		nc.serverMu.Lock()
		nc.serverConns[udpAddr.String()] = peer
		nc.serverMu.Unlock()

		flog.Debugf("nfqueue transport: accepted connection from %s", udpAddr)
		go nc.readTCPLoop(conn, udpAddr)
	}
}

// readTCPLoop reads length-prefixed frames from a TCP connection.
// In NFQUEUE mode, data still flows through the kernel TCP stack;
// NFQUEUE only intercepts for header modification.
func (nc *NFQueuePacketConn) readTCPLoop(conn net.Conn, addr *net.UDPAddr) {
	defer func() {
		conn.Close()
		if nc.isServer {
			nc.serverMu.Lock()
			delete(nc.serverConns, addr.String())
			nc.serverMu.Unlock()
		}
	}()

	header := make([]byte, 4)
	for {
		select {
		case <-nc.ctx.Done():
			return
		default:
		}

		if _, err := readFull(conn, header); err != nil {
			if nc.ctx.Err() == nil {
				flog.Debugf("nfqueue transport: read header error from %s: %v", addr, err)
			}
			return
		}

		frameLen := binary.BigEndian.Uint32(header)
		if frameLen == 0 || frameLen > 65535 {
			flog.Errorf("nfqueue transport: invalid frame length %d from %s", frameLen, addr)
			return
		}

		payload := make([]byte, frameLen)
		if _, err := readFull(conn, payload); err != nil {
			if nc.ctx.Err() == nil {
				flog.Debugf("nfqueue transport: read payload error from %s: %v", addr, err)
			}
			return
		}

		// Evasion: unwrap first packet (stream level)
		if nc.evasionOn && nc.entropyMgr != nil && nc.probeResist != nil {
			addrKey := addr.String()
			if _, loaded := nc.firstRecv.LoadOrStore(addrKey, true); !loaded {
				unwrapped, err := nc.entropyMgr.UnwrapFirstPacket(payload)
				if err != nil {
					flog.Debugf("nfqueue transport: entropy unwrap failed from %s: %v", addrKey, err)
					nc.firstRecv.Delete(addrKey)
					continue
				}
				kcpPayload, valid, err := nc.probeResist.ExtractAndValidate(unwrapped)
				if err != nil || !valid {
					flog.Debugf("nfqueue transport: auth failed from %s (valid=%v, err=%v)", addrKey, valid, err)
					nc.firstRecv.Delete(addrKey)
					continue
				}
				flog.Debugf("nfqueue transport: first packet unwrapped from %s", addrKey)
				payload = kcpPayload
			}
		}

		select {
		case nc.readCh <- nfqFrame{data: payload, addr: addr}:
		case <-nc.ctx.Done():
			return
		}
	}
}

// readFull reads exactly len(buf) bytes from r, like io.ReadFull.
func readFull(r net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := r.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// ensureClientConn creates the client TCP connection on first write.
func (nc *NFQueuePacketConn) ensureClientConn(addr *net.UDPAddr) (net.Conn, error) {
	if nc.conn != nil {
		return nc.conn, nil
	}

	tcpAddr := &net.TCPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("nfqueue transport: dial %s failed: %w", tcpAddr, err)
	}

	nc.conn = conn
	nc.remoteAddr = addr

	flog.Infof("nfqueue transport: connected to %s", addr)
	go nc.readTCPLoop(conn, addr)

	return conn, nil
}

func (nc *NFQueuePacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := nc.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-nc.ctx.Done():
		return 0, nc.ctx.Err()
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
	if nc.evasionOn && nc.entropyMgr != nil && nc.probeResist != nil {
		addrKey := daddr.String()
		if _, loaded := nc.firstSend.LoadOrStore(addrKey, true); !loaded {
			authed, err := nc.probeResist.PrependAuthToken(payload)
			if err != nil {
				flog.Errorf("nfqueue transport: auth token failed: %v", err)
			} else {
				wrapped, err := nc.entropyMgr.WrapFirstPacket(authed)
				if err != nil {
					flog.Errorf("nfqueue transport: entropy wrap failed: %v", err)
					payload = authed
				} else {
					payload = wrapped
					flog.Debugf("nfqueue transport: first packet wrapped (%d bytes) for %s", len(payload), addrKey)
				}
			}
		}
	}

	// Get or create connection
	var conn net.Conn
	var err error
	if nc.isServer {
		nc.serverMu.RLock()
		peer, ok := nc.serverConns[daddr.String()]
		nc.serverMu.RUnlock()
		if !ok {
			return 0, fmt.Errorf("nfqueue transport: no connection to %s", daddr)
		}
		conn = peer.conn
	} else {
		conn, err = nc.ensureClientConn(daddr)
		if err != nil {
			return 0, err
		}
	}

	// Write length-prefixed frame (same framing as TCP transport)
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)

	if _, err := conn.Write(frame); err != nil {
		return 0, fmt.Errorf("nfqueue transport: write error: %w", err)
	}

	return len(data), nil
}

func (nc *NFQueuePacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := nc.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-nc.ctx.Done():
		return 0, nil, nc.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	case frame := <-nc.readCh:
		n := copy(data, frame.data)
		return n, frame.addr, nil
	}
}

func (nc *NFQueuePacketConn) Close() error {
	nc.cancel()

	if nc.outNfq != nil {
		nc.outNfq.Close()
	}
	if nc.inNfq != nil {
		nc.inNfq.Close()
	}
	if nc.listener != nil {
		nc.listener.Close()
	}
	if nc.conn != nil {
		nc.conn.Close()
	}

	nc.serverMu.RLock()
	for _, peer := range nc.serverConns {
		peer.conn.Close()
	}
	nc.serverMu.RUnlock()

	return nil
}

func (nc *NFQueuePacketConn) LocalAddr() net.Addr {
	if nc.listener != nil {
		return nc.listener.Addr()
	}
	if nc.conn != nil {
		return nc.conn.LocalAddr()
	}
	return nil
}

func (nc *NFQueuePacketConn) SetDeadline(t time.Time) error {
	nc.readDeadline.Store(t)
	nc.writeDeadline.Store(t)
	return nil
}

func (nc *NFQueuePacketConn) SetReadDeadline(t time.Time) error {
	nc.readDeadline.Store(t)
	return nil
}

func (nc *NFQueuePacketConn) SetWriteDeadline(t time.Time) error {
	nc.writeDeadline.Store(t)
	return nil
}

// parseIPTCPPacket parses an IP packet to find TCP payload offset and source address.
// Returns (ipPayload, tcpPayloadOffset from start of pktData, source UDPAddr).
func parseIPTCPPacket(pktData []byte) ([]byte, int, *net.UDPAddr) {
	if len(pktData) < 20 {
		return nil, 0, nil
	}

	addr := &net.UDPAddr{}
	var ipHeaderLen int
	var protocol byte

	version := pktData[0] >> 4
	switch version {
	case 4:
		ipHeaderLen = int(pktData[0]&0x0f) * 4
		if len(pktData) < ipHeaderLen {
			return nil, 0, nil
		}
		protocol = pktData[9]
		addr.IP = net.IP(pktData[12:16])
	case 6:
		ipHeaderLen = 40
		if len(pktData) < ipHeaderLen {
			return nil, 0, nil
		}
		protocol = pktData[6] // Next Header
		addr.IP = net.IP(pktData[8:24])
	default:
		return nil, 0, nil
	}

	// Only handle TCP (protocol 6)
	if protocol != 6 {
		return nil, 0, nil
	}

	tcpStart := ipHeaderLen
	if len(pktData) < tcpStart+20 {
		return nil, 0, nil
	}

	srcPort := binary.BigEndian.Uint16(pktData[tcpStart : tcpStart+2])
	addr.Port = int(srcPort)

	dataOffset := int(pktData[tcpStart+12]>>4) * 4
	tcpPayloadStart := tcpStart + dataOffset

	if tcpPayloadStart > len(pktData) {
		return nil, 0, nil
	}

	return pktData[ipHeaderLen:], tcpPayloadStart, addr
}

// normalizeTCPHeaders applies TCP fingerprint normalization to raw IP packet bytes.
// Returns modified packet bytes or nil if no modification needed.
func normalizeTCPHeaders(pktData []byte, tcpFP *evasion.TCPFingerprint) []byte {
	if len(pktData) < 40 { // minimum IP + TCP header
		return nil
	}

	version := pktData[0] >> 4
	var ipHeaderLen int
	switch version {
	case 4:
		ipHeaderLen = int(pktData[0]&0x0f) * 4
		// Normalize IPv4: TTL=64, DF flag
		pktData[8] = 64 // TTL
		pktData[6] = (pktData[6] & 0x1F) | 0x40 // Set DF flag
	case 6:
		ipHeaderLen = 40
		pktData[7] = 64 // Hop Limit
	default:
		return nil
	}

	if len(pktData) < ipHeaderLen+20 {
		return nil
	}

	// TCP header starts after IP header
	// We could modify TCP options here if needed
	// For now, the kernel's TCP options are natural (which is a benefit)

	return pktData
}
