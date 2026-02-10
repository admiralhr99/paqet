//go:build linux

package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/flog"

	"golang.org/x/sys/unix"
)

// NFQUEUE constants from linux/netfilter.h and linux/netfilter/nfnetlink_queue.h
const (
	nfnlSubsysQueue = 3

	// Message types
	nfqnlMsgPacket       = 0 // Packet from kernel
	nfqnlMsgVerdict      = 1 // Verdict from userspace
	nfqnlMsgConfig       = 2 // Configuration message
	nfqnlMsgVerdictBatch = 3

	// Config commands
	nfqnlCfgCmdBind   = 1
	nfqnlCfgCmdUnbind = 2

	// Config attribute types
	nfqaCfgCmd       = 1
	nfqaCfgParams    = 2
	nfqaCfgQueueMaxLen = 3

	// Packet attribute types
	nfqaPacketHdr  = 1
	nfqaPayload    = 9
	nfqaMark       = 3
	nfqaVerdictHdr = 4

	// Verdicts
	nfAccept = 1
	nfDrop   = 0

	// Copy modes
	nfqnlCopyPacket = 2

	afInet  = 2
	afInet6 = 10
)

// linuxNfqHandle implements nfqHandle for Linux using raw netlink sockets.
type linuxNfqHandle struct {
	fd       int
	queueNum uint16
	cancel   context.CancelFunc
}

func (h *linuxNfqHandle) Close() error {
	h.cancel()
	return unix.Close(h.fd)
}

// startNFQueue opens a netlink NFQUEUE socket, binds to the given queue number,
// and starts processing packets in a goroutine.
func startNFQueue(ctx context.Context, queueNum uint16, handler nfqPacketHandler) (nfqHandle, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink socket: %w", err)
	}

	// Bind to netlink
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 0,
		Pid:    0, // let kernel assign
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind netlink socket: %w", err)
	}

	// Set receive buffer size
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024)

	// Send bind command
	if err := nfqSendConfig(fd, queueNum, nfqnlCfgCmdBind); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind to queue %d: %w", queueNum, err)
	}

	// Set copy mode to copy entire packet
	if err := nfqSetCopyMode(fd, queueNum, nfqnlCopyPacket, 65535); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set copy mode: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	h := &linuxNfqHandle{fd: fd, queueNum: queueNum, cancel: cancel}

	go nfqProcessLoop(ctx, fd, queueNum, handler)

	return h, nil
}

// nfqProcessLoop reads packets from the NFQUEUE and processes them.
func nfqProcessLoop(ctx context.Context, fd int, queueNum uint16, handler nfqPacketHandler) {
	buf := make([]byte, 65536+512) // max packet + netlink overhead
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			flog.Debugf("nfqueue: recvfrom error on queue %d: %v", queueNum, err)
			continue
		}
		if n < 16 { // minimum netlink header
			continue
		}

		// Parse netlink message
		data := buf[:n]
		packetID, payload := nfqParsePacket(data)
		if packetID == 0 || payload == nil {
			continue
		}

		// Call handler
		modifiedPayload, accept := handler(payload)
		_ = modifiedPayload

		// Send verdict
		verdict := nfAccept
		if !accept {
			verdict = nfDrop
		}

		if err := nfqSendVerdict(fd, queueNum, packetID, uint32(verdict)); err != nil {
			flog.Debugf("nfqueue: verdict error on queue %d: %v", queueNum, err)
		}
	}
}

// nfqSendConfig sends a configuration command to the queue.
func nfqSendConfig(fd int, queueNum uint16, cmd uint8) error {
	// Build netlink message with NFQUEUE config
	msgType := uint16(nfnlSubsysQueue<<8) | uint16(nfqnlMsgConfig)

	// Config command attribute
	// struct nfqnl_msg_config_cmd { uint8 command; uint8 _pad; uint16 pf; }
	cmdData := make([]byte, 4)
	cmdData[0] = cmd
	binary.BigEndian.PutUint16(cmdData[2:4], afInet) // AF_INET

	cmdAttr := nlaEncode(nfqaCfgCmd, cmdData)

	// nfgenmsg header: { uint8 nfgen_family; uint8 version; uint16 res_id }
	nfgenMsg := make([]byte, 4)
	nfgenMsg[0] = afInet // family
	nfgenMsg[1] = 0      // version (NFNETLINK_V0)
	binary.BigEndian.PutUint16(nfgenMsg[2:4], queueNum)

	payload := append(nfgenMsg, cmdAttr...)

	return nlSend(fd, msgType, payload)
}

// nfqSetCopyMode sets the copy mode for the queue.
func nfqSetCopyMode(fd int, queueNum uint16, mode uint8, rangeSize uint32) error {
	msgType := uint16(nfnlSubsysQueue<<8) | uint16(nfqnlMsgConfig)

	// struct nfqnl_msg_config_params { uint32 copy_range; uint8 copy_mode; }
	params := make([]byte, 8)
	binary.BigEndian.PutUint32(params[0:4], rangeSize)
	params[4] = mode

	paramsAttr := nlaEncode(nfqaCfgParams, params)

	nfgenMsg := make([]byte, 4)
	nfgenMsg[0] = afInet
	nfgenMsg[1] = 0
	binary.BigEndian.PutUint16(nfgenMsg[2:4], queueNum)

	payload := append(nfgenMsg, paramsAttr...)

	return nlSend(fd, msgType, payload)
}

// nfqSendVerdict sends a verdict for a packet.
func nfqSendVerdict(fd int, queueNum uint16, packetID uint32, verdict uint32) error {
	msgType := uint16(nfnlSubsysQueue<<8) | uint16(nfqnlMsgVerdict)

	// Verdict header: { uint32 verdict; uint32 id; }
	verdictData := make([]byte, 8)
	binary.BigEndian.PutUint32(verdictData[0:4], verdict)
	binary.BigEndian.PutUint32(verdictData[4:8], packetID)

	verdictAttr := nlaEncode(nfqaVerdictHdr, verdictData)

	nfgenMsg := make([]byte, 4)
	nfgenMsg[0] = afInet
	nfgenMsg[1] = 0
	binary.BigEndian.PutUint16(nfgenMsg[2:4], queueNum)

	payload := append(nfgenMsg, verdictAttr...)

	return nlSend(fd, msgType, payload)
}

// nfqParsePacket extracts packet ID and payload from a netlink message.
func nfqParsePacket(data []byte) (uint32, []byte) {
	// Skip netlink header (16 bytes) and nfgenmsg (4 bytes)
	if len(data) < 20 {
		return 0, nil
	}

	// Check message type
	msgType := binary.LittleEndian.Uint16(data[4:6])
	expectedType := uint16(nfnlSubsysQueue<<8) | uint16(nfqnlMsgPacket)
	if msgType != expectedType {
		return 0, nil
	}

	attrs := data[20:] // skip nlmsghdr(16) + nfgenmsg(4)
	var packetID uint32
	var payload []byte

	// Parse netlink attributes
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & 0x7FFF // mask NLA_F_NESTED etc.

		if attrLen < 4 || int(attrLen) > len(attrs) {
			break
		}

		attrData := attrs[4:attrLen]

		switch attrType {
		case nfqaPacketHdr:
			// struct nfqnl_msg_packet_hdr { uint32 packet_id; ... }
			if len(attrData) >= 4 {
				packetID = binary.BigEndian.Uint32(attrData[0:4])
			}
		case nfqaPayload:
			payload = make([]byte, len(attrData))
			copy(payload, attrData)
		}

		// Advance to next attribute (aligned to 4 bytes)
		alignedLen := (int(attrLen) + 3) & ^3
		if alignedLen > len(attrs) {
			break
		}
		attrs = attrs[alignedLen:]
	}

	return packetID, payload
}

// nlSend sends a netlink message.
func nlSend(fd int, msgType uint16, payload []byte) error {
	totalLen := 16 + len(payload) // nlmsghdr(16) + payload
	msg := make([]byte, totalLen)

	// Netlink message header
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))   // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:6], msgType)             // nlmsg_type
	binary.LittleEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST)  // nlmsg_flags
	binary.LittleEndian.PutUint32(msg[8:12], 0)                  // nlmsg_seq
	binary.LittleEndian.PutUint32(msg[12:16], 0)                 // nlmsg_pid

	copy(msg[16:], payload)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(fd, msg, 0, sa)
}

// nlaEncode encodes a netlink attribute.
func nlaEncode(attrType uint16, data []byte) []byte {
	attrLen := 4 + len(data)
	// Pad to 4 bytes
	padLen := (attrLen + 3) & ^3
	buf := make([]byte, padLen)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(attrLen))
	binary.LittleEndian.PutUint16(buf[2:4], attrType)
	copy(buf[4:], data)
	return buf
}

// Ensure linuxNfqHandle implements nfqHandle.
var _ nfqHandle = (*linuxNfqHandle)(nil)

// Ensure NFQueuePacketConn implements net.PacketConn.
var _ net.PacketConn = (*NFQueuePacketConn)(nil)
