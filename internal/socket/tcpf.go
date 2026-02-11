package socket

import (
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"sync"
)

// TCPF manages per-connection TCP flag iterators. Used by both pcap and TUN transports.
type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

func (t *TCPF) getClientTCPF(dstIP []byte, dstPort uint16) conf.TCPF {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if ff := t.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return t.tcpF.Next()
}

func (t *TCPF) setClientTCPF(ip []byte, port uint16, f []conf.TCPF) {
	t.mu.Lock()
	t.clientTCPF[hash.IPAddr(ip, port)] = &iterator.Iterator[conf.TCPF]{Items: f}
	t.mu.Unlock()
}
