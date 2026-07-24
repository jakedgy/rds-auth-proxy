// Package proxy implements a small, database-protocol-agnostic TCP proxy.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Config controls a Proxy.
type Config struct {
	ListenAddress string
	Endpoint      string
	DialTimeout   time.Duration
	Logger        *slog.Logger
}

// Proxy forwards local TCP connections to an RDS endpoint. TLS remains
// end-to-end between the database client and RDS.
type Proxy struct {
	config Config
}

// New validates config and constructs a Proxy.
func New(config Config) (*Proxy, error) {
	if config.ListenAddress == "" {
		return nil, errors.New("listen address is required")
	}
	host, _, err := net.SplitHostPort(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid RDS endpoint: %w", err)
	}
	if host == "" {
		return nil, errors.New("RDS endpoint host is required")
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Proxy{config: config}, nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (p *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		go p.handle(ctx, connection)
	}
}

func (p *Proxy) handle(ctx context.Context, downstream net.Conn) {
	defer downstream.Close()
	dialer := &net.Dialer{Timeout: p.config.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", p.config.Endpoint)
	if err != nil {
		p.config.Logger.Error("upstream connection failed", "remote", downstream.RemoteAddr(), "error", err)
		return
	}
	defer upstream.Close()

	p.config.Logger.Debug("connection opened", "remote", downstream.RemoteAddr())
	defer p.config.Logger.Debug("connection closed", "remote", downstream.RemoteAddr())

	var wg sync.WaitGroup
	wg.Add(2)
	copyConnection := func(destination, source net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	go copyConnection(upstream, downstream)
	go copyConnection(downstream, upstream)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-ctx.Done():
		_ = upstream.Close()
	case <-done:
	}
}
