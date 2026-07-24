package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

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
	proxy, err := New(Config{ListenAddress: "127.0.0.1:0", Endpoint: "db.example.com:5432"})
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
