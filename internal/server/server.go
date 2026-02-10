package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
)

type Server struct {
	cfg   *conf.Conf
	pConn net.PacketConn
	wg    sync.WaitGroup
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	// For TCP and NFQUEUE modes, ensure the listen port is set on the network config
	// since those modes derive the server port from cfg.Network.Port
	if (s.cfg.Network.Mode == "tcp" || s.cfg.Network.Mode == "nfqueue") && s.cfg.Network.Port == 0 {
		if s.cfg.Listen.Addr != nil {
			s.cfg.Network.Port = s.cfg.Listen.Addr.Port
		}
	}

	pConn, err := socket.NewPacketConn(ctx, &s.cfg.Network, &s.cfg.Evasion)
	if err != nil {
		return fmt.Errorf("could not create packet conn: %w", err)
	}
	s.pConn = pConn

	listener, err := kcp.Listen(s.cfg.Transport.KCP, pConn)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()
	flog.Infof("Server started - listening for packets on :%d", s.cfg.Listen.Addr.Port)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.listen(ctx, listener)
	}()

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			flog.Errorf("failed to accept connection: %v", err)
			continue
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handleConn(ctx, conn)
		}()
	}
}
