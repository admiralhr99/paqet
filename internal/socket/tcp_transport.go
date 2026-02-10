package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/evasion"
	"paqet/internal/flog"
	"sync"
	"sync/atomic"
	"time"
)

// TCPPacketConn wraps a kernel TCP connection to implement net.PacketConn.
// KCP packets are length-prefix framed over the TCP stream.
//
// Frame format: [4 bytes big-endian length][payload]
//
// Server mode: listens on a TCP port, accepts connections from multiple clients.
// Client mode: dials a single TCP connection to the server.
type TCPPacketConn struct {
	listener   net.Listener
	remoteAddr *net.UDPAddr // server address (client mode)
	isServer   bool

	// Active connections
	clientConn net.Conn              // single connection (client mode)
	serverMu   sync.RWMutex          // protects serverConns
	serverConns map[string]*tcpPeer  // addr string -> peer (server mode)

	// Evasion
	evasionOn   bool
	entropyMgr  *evasion.EntropyManager
	probeResist *evasion.ProbeResistance
	firstSend   sync.Map // tracks first packet per destination
	firstRecv   sync.Map // tracks first packet per source

	// Read channel: incoming packets from all TCP connections
	readCh chan tcpFrame

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
}

type tcpPeer struct {
	conn net.Conn
	addr *net.UDPAddr
}

type tcpFrame struct {
	data []byte
	addr *net.UDPAddr
}

const (
	tcpFrameHeaderLen = 4
	tcpMaxFrameSize   = 65535
)

// NewTCPPacketConn creates a kernel-TCP based PacketConn.
// In server mode (cfg.Port > 0 or role=server), it listens for TCP connections.
// In client mode, it dials the server when first WriteTo is called.
func NewTCPPacketConn(ctx context.Context, cfg *conf.Network, evCfg *conf.Evasion) (*TCPPacketConn, error) {
	ctx, cancel := context.WithCancel(ctx)

	tc := &TCPPacketConn{
		isServer:    cfg.Port > 0,
		serverConns: make(map[string]*tcpPeer),
		readCh:      make(chan tcpFrame, 256),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize evasion if enabled
	if evCfg != nil && evCfg.Enabled() {
		tc.evasionOn = true
		tc.entropyMgr = evasion.NewEntropyManager(evCfg.EntropyMode, evCfg.SNI)
		tc.probeResist = evasion.NewProbeResistance(evCfg.AuthSecret, evCfg.FallbackURL)
		flog.Infof("tcp transport: evasion enabled: mode=%s sni=%s", evCfg.EntropyMode, evCfg.SNI)
	}

	if tc.isServer {
		listenAddr := fmt.Sprintf(":%d", cfg.Port)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("tcp transport: failed to listen on %s: %w", listenAddr, err)
		}
		tc.listener = ln
		flog.Infof("tcp transport: server listening on %s", listenAddr)

		go tc.acceptLoop()
	}

	return tc, nil
}

// acceptLoop accepts incoming TCP connections (server mode).
func (tc *TCPPacketConn) acceptLoop() {
	for {
		conn, err := tc.listener.Accept()
		if err != nil {
			select {
			case <-tc.ctx.Done():
				return
			default:
				flog.Errorf("tcp transport: accept error: %v", err)
				continue
			}
		}

		tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
		udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
		peer := &tcpPeer{conn: conn, addr: udpAddr}

		tc.serverMu.Lock()
		tc.serverConns[udpAddr.String()] = peer
		tc.serverMu.Unlock()

		flog.Debugf("tcp transport: accepted connection from %s", udpAddr)
		go tc.readLoop(conn, udpAddr)
	}
}

// readLoop reads length-prefixed frames from a TCP connection and sends them to readCh.
func (tc *TCPPacketConn) readLoop(conn net.Conn, addr *net.UDPAddr) {
	defer func() {
		conn.Close()
		if tc.isServer {
			tc.serverMu.Lock()
			delete(tc.serverConns, addr.String())
			tc.serverMu.Unlock()
		}
		flog.Debugf("tcp transport: connection from %s closed", addr)
	}()

	header := make([]byte, tcpFrameHeaderLen)
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
		}

		// Read frame header (4 bytes length)
		if _, err := io.ReadFull(conn, header); err != nil {
			if err != io.EOF && tc.ctx.Err() == nil {
				flog.Debugf("tcp transport: read header error from %s: %v", addr, err)
			}
			return
		}

		frameLen := binary.BigEndian.Uint32(header)
		if frameLen == 0 || frameLen > tcpMaxFrameSize {
			flog.Errorf("tcp transport: invalid frame length %d from %s", frameLen, addr)
			return
		}

		// Read frame payload
		payload := make([]byte, frameLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			if tc.ctx.Err() == nil {
				flog.Debugf("tcp transport: read payload error from %s: %v", addr, err)
			}
			return
		}

		// Evasion: unwrap first packet
		if tc.evasionOn && tc.entropyMgr != nil && tc.probeResist != nil {
			addrKey := addr.String()
			if _, loaded := tc.firstRecv.LoadOrStore(addrKey, true); !loaded {
				unwrapped, err := tc.entropyMgr.UnwrapFirstPacket(payload)
				if err != nil {
					flog.Debugf("tcp transport: entropy unwrap failed from %s: %v", addrKey, err)
					tc.firstRecv.Delete(addrKey)
					continue
				}
				kcpPayload, valid, err := tc.probeResist.ExtractAndValidate(unwrapped)
				if err != nil || !valid {
					flog.Debugf("tcp transport: auth failed from %s (valid=%v, err=%v)", addrKey, valid, err)
					tc.firstRecv.Delete(addrKey)
					continue
				}
				flog.Debugf("tcp transport: first packet unwrapped from %s (%d -> %d bytes)", addrKey, len(payload), len(kcpPayload))
				payload = kcpPayload
			}
		}

		select {
		case tc.readCh <- tcpFrame{data: payload, addr: addr}:
		case <-tc.ctx.Done():
			return
		}
	}
}

// ensureClientConn lazily creates the client TCP connection on first write.
func (tc *TCPPacketConn) ensureClientConn(addr *net.UDPAddr) (net.Conn, error) {
	if tc.clientConn != nil {
		return tc.clientConn, nil
	}

	tcpAddr := &net.TCPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp transport: dial %s failed: %w", tcpAddr, err)
	}

	tc.clientConn = conn
	tc.remoteAddr = addr

	flog.Infof("tcp transport: connected to %s", addr)

	// Start reading from server
	go tc.readLoop(conn, addr)

	return conn, nil
}

func (tc *TCPPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
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
				flog.Errorf("tcp transport: auth token failed: %v", err)
			} else {
				wrapped, err := tc.entropyMgr.WrapFirstPacket(authed)
				if err != nil {
					flog.Errorf("tcp transport: entropy wrap failed: %v", err)
					payload = authed
				} else {
					payload = wrapped
					flog.Debugf("tcp transport: first packet wrapped (%d bytes) for %s", len(payload), addrKey)
				}
			}
		}
	}

	// Get or create connection
	var conn net.Conn
	var err error
	if tc.isServer {
		tc.serverMu.RLock()
		peer, ok := tc.serverConns[daddr.String()]
		tc.serverMu.RUnlock()
		if !ok {
			return 0, fmt.Errorf("tcp transport: no connection to %s", daddr)
		}
		conn = peer.conn
	} else {
		conn, err = tc.ensureClientConn(daddr)
		if err != nil {
			return 0, err
		}
	}

	// Write length-prefixed frame
	frame := make([]byte, tcpFrameHeaderLen+len(payload))
	binary.BigEndian.PutUint32(frame[:tcpFrameHeaderLen], uint32(len(payload)))
	copy(frame[tcpFrameHeaderLen:], payload)

	if _, err := conn.Write(frame); err != nil {
		return 0, fmt.Errorf("tcp transport: write error: %w", err)
	}

	return len(data), nil
}

func (tc *TCPPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
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

func (tc *TCPPacketConn) Close() error {
	tc.cancel()

	if tc.listener != nil {
		tc.listener.Close()
	}
	if tc.clientConn != nil {
		tc.clientConn.Close()
	}

	tc.serverMu.RLock()
	for _, peer := range tc.serverConns {
		peer.conn.Close()
	}
	tc.serverMu.RUnlock()

	return nil
}

func (tc *TCPPacketConn) LocalAddr() net.Addr {
	if tc.listener != nil {
		return tc.listener.Addr()
	}
	if tc.clientConn != nil {
		return tc.clientConn.LocalAddr()
	}
	return nil
}

func (tc *TCPPacketConn) SetDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	tc.writeDeadline.Store(t)
	return nil
}

func (tc *TCPPacketConn) SetReadDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	return nil
}

func (tc *TCPPacketConn) SetWriteDeadline(t time.Time) error {
	tc.writeDeadline.Store(t)
	return nil
}
