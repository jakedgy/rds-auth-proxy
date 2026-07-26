package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type staticTokenProvider struct{ token string }

func (p staticTokenProvider) Token(context.Context, string) (string, error) { return p.token, nil }

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config Config
	}{
		{"missing listen address", Config{Endpoint: "db.example.com:5432"}},
		{"missing endpoint", Config{ListenAddress: "127.0.0.1:0"}},
		{"missing endpoint port", Config{ListenAddress: "127.0.0.1:0", Endpoint: "db.example.com"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(test.config); err == nil {
				t.Fatal("New() returned nil error")
			}
		})
	}
}

func TestServeStopsWhenContextIsCancelled(t *testing.T) {
	proxy, err := New(Config{ListenAddress: "127.0.0.1:0", Endpoint: "db.example.com:5432", TokenProvider: staticTokenProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ctx, listener) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
}

func TestReadStartupRejectsClientTLSAndExtractsUser(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ssl := make([]byte, 8)
		binary.BigEndian.PutUint32(ssl, 8)
		binary.BigEndian.PutUint32(ssl[4:], sslRequestCode)
		_, _ = client.Write(ssl)
		response := make([]byte, 1)
		_, _ = io.ReadFull(client, response)
		if response[0] != 'N' {
			t.Errorf("SSL response = %q, want N", response)
		}
		payload := append([]byte{0, 3, 0, 0}, []byte("user\x00app_user\x00database\x00app\x00\x00")...)
		message := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(message, uint32(len(message)))
		copy(message[4:], payload)
		_, _ = client.Write(message)
	}()
	message, user, err := readStartup(server)
	if err != nil {
		t.Fatal(err)
	}
	if user != "app_user" {
		t.Fatalf("user = %q, want app_user", user)
	}
	if len(message) == 0 {
		t.Fatal("startup message is empty")
	}
	_ = server.Close()
	_ = client.Close()
	<-done
}

func TestAuthenticateInjectsTokenWithoutPromptingClient(t *testing.T) {
	dServer, dClient := net.Pipe()
	uProxy, uServer := net.Pipe()
	p := &Proxy{config: Config{TokenProvider: staticTokenProvider{token: "iam-token"}}}
	done := make(chan error, 1)
	go func() { done <- p.authenticate(context.Background(), dServer, uProxy, "app_user") }()

	go func() {
		cleartext := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
		_, _ = uServer.Write(cleartext)
		password := make([]byte, 15)
		_, _ = io.ReadFull(uServer, password)
		if string(password[5:]) != "iam-token\x00" {
			t.Errorf("injected password = %q", password[5:])
		}
		_, _ = uServer.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
	}()

	authOK := make([]byte, 9)
	if _, err := io.ReadFull(dClient, authOK); err != nil {
		t.Fatal(err)
	}
	if authOK[0] != 'R' || binary.BigEndian.Uint32(authOK[5:]) != 0 {
		t.Fatalf("client response = %v, want AuthenticationOk", authOK)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = dClient.Close()
	_ = dServer.Close()
	_ = uProxy.Close()
	_ = uServer.Close()
}
