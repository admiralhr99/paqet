//go:build !linux

package socket

import (
	"context"
	"fmt"
)

type stubNfqHandle struct{}

func (h *stubNfqHandle) Close() error { return nil }

func startNFQueue(ctx context.Context, queueNum uint16, handler nfqPacketHandler) (nfqHandle, error) {
	return nil, fmt.Errorf("NFQUEUE transport is only supported on Linux")
}
