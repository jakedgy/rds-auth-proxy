// Package proxy implements a PostgreSQL-aware RDS IAM authentication proxy.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	protocolVersion3  = 196608
)

// TokenProvider creates an IAM database authentication token for a user.
type TokenProvider interface {
	Token(context.Context, string) (string, error)
}

// Config controls a Proxy.
type Config struct {
	ListenAddress string
	Endpoint      string
	DialTimeout   time.Duration
	TLSConfig     *tls.Config
	DirectTLS     bool
	TokenProvider TokenProvider
	Logger        *slog.Logger
}

// Proxy accepts plaintext PostgreSQL connections locally and uses TLS and a
// freshly generated IAM token for every upstream connection.
type Proxy struct{ config Config }

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
	if config.TokenProvider == nil {
		return nil, errors.New("token provider is required")
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	if config.TLSConfig.ServerName == "" {
		config.TLSConfig = config.TLSConfig.Clone()
		config.TLSConfig.ServerName = host
	}
	return &Proxy{config: config}, nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (p *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	go func() { <-ctx.Done(); _ = listener.Close() }()
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
	startup, user, err := readStartup(downstream)
	if err != nil {
		p.config.Logger.Debug("invalid PostgreSQL startup", "error", err)
		return
	}

	dialer := &net.Dialer{Timeout: p.config.DialTimeout}
	rawUpstream, err := dialer.DialContext(ctx, "tcp", p.config.Endpoint)
	if err != nil {
		p.config.Logger.Error("upstream connection failed", "error", err)
		return
	}
	defer rawUpstream.Close()
	if !p.config.DirectTLS {
		if err := requestTLS(rawUpstream); err != nil {
			p.config.Logger.Error("upstream TLS negotiation failed", "error", err)
			return
		}
	}
	upstream := tls.Client(rawUpstream, p.config.TLSConfig.Clone())
	if err := upstream.HandshakeContext(ctx); err != nil {
		p.config.Logger.Error("upstream TLS handshake failed", "error", err)
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(startup); err != nil {
		return
	}

	if err := p.authenticate(ctx, downstream, upstream, user); err != nil {
		p.config.Logger.Error("PostgreSQL authentication failed", "user", user, "error", err)
		return
	}
	p.config.Logger.Debug("connection opened", "remote", downstream.RemoteAddr(), "user", user)
	relay(ctx, downstream, upstream)
}

func readStartup(conn net.Conn) ([]byte, string, error) {
	for {
		message, err := readLengthMessage(conn)
		if err != nil {
			return nil, "", err
		}
		if len(message) < 8 {
			return nil, "", errors.New("startup message is too short")
		}
		code := binary.BigEndian.Uint32(message[4:8])
		if code == sslRequestCode || code == gssEncRequestCode {
			// The local connection is intentionally plaintext; TLS is established on
			// the independent upstream connection so the proxy can inject the token.
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, "", err
			}
			continue
		}
		if code != protocolVersion3 {
			return nil, "", fmt.Errorf("unsupported PostgreSQL protocol %d", code)
		}
		user := startupParameter(message[8:], "user")
		if user == "" {
			return nil, "", errors.New("PostgreSQL startup message has no user")
		}
		return message, user, nil
	}
}

func startupParameter(payload []byte, wanted string) string {
	parts := strings.Split(string(payload), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == wanted {
			return parts[i+1]
		}
	}
	return ""
}

func requestTLS(conn net.Conn) error {
	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request, 8)
	binary.BigEndian.PutUint32(request[4:], sslRequestCode)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 'S' {
		return fmt.Errorf("server refused TLS (response %q)", response[0])
	}
	return nil
}

func (p *Proxy) authenticate(ctx context.Context, downstream, upstream net.Conn, user string) error {
	for {
		typ, message, err := readTypedMessage(upstream)
		if err != nil {
			return err
		}
		if typ != 'R' {
			if _, err := downstream.Write(append([]byte{typ}, message...)); err != nil {
				return err
			}
			if typ == 'E' {
				return errors.New("server rejected connection")
			}
			continue
		}
		if len(message) < 8 {
			return errors.New("short authentication message")
		}
		authType := binary.BigEndian.Uint32(message[4:8])
		switch authType {
		case 0:
			_, err := downstream.Write(append([]byte{'R'}, message...))
			return err
		case 3:
			token, err := p.config.TokenProvider.Token(ctx, user)
			if err != nil {
				return fmt.Errorf("generate IAM token: %w", err)
			}
			password := append([]byte(token), 0)
			packet := make([]byte, 5+len(password))
			packet[0] = 'p'
			binary.BigEndian.PutUint32(packet[1:], uint32(4+len(password)))
			copy(packet[5:], password)
			if _, err := upstream.Write(packet); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported PostgreSQL authentication method %d; RDS IAM authentication must use cleartext password over TLS", authType)
		}
	}
}

func readLengthMessage(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length < 4 || length > 1<<20 {
		return nil, fmt.Errorf("invalid PostgreSQL message length %d", length)
	}
	message := make([]byte, length)
	copy(message, header)
	_, err := io.ReadFull(reader, message[4:])
	return message, err
}

func readTypedMessage(reader io.Reader) (byte, []byte, error) {
	var typ [1]byte
	if _, err := io.ReadFull(reader, typ[:]); err != nil {
		return 0, nil, err
	}
	message, err := readLengthMessage(reader)
	return typ[0], message, err
}

func relay(ctx context.Context, downstream, upstream net.Conn) {
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
		_ = downstream.Close()
	case <-done:
	}
}
