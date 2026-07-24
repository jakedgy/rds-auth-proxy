package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	healthHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Body.String() != "ok\n" {
		t.Fatalf("body = %q, want %q", response.Body.String(), "ok\n")
	}
}

func TestRunTokenPrintsExplicitRootPath(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = originalStdout
	})

	runErr := runToken(context.Background(), []string{
		"--endpoint", "database.example.com:5432",
		"--region", "us-east-1",
		"--user", "postgres",
	})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = originalStdout
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}

	token := strings.TrimSpace(string(output))
	if !strings.HasPrefix(token, "database.example.com:5432/?") {
		t.Fatalf("token prefix = %q, want explicit root path", token[:strings.IndexByte(token, '?')+1])
	}
}

func TestWithExplicitRootPath(t *testing.T) {
	tests := map[string]struct {
		token string
		want  string
	}{
		"missing root path": {
			token: "database.example.com:5432?Action=connect",
			want:  "database.example.com:5432/?Action=connect",
		},
		"existing root path": {
			token: "database.example.com:5432/?Action=connect",
			want:  "database.example.com:5432/?Action=connect",
		},
		"no query": {
			token: "database.example.com:5432",
			want:  "database.example.com:5432",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := withExplicitRootPath(test.token); got != test.want {
				t.Fatalf("withExplicitRootPath(%q) = %q, want %q", test.token, got, test.want)
			}
		})
	}
}

func TestRunProxyReturnsHealthListenerBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	runErr := runProxy(context.Background(), []string{
		"--endpoint", "database.example.com:5432",
		"--listen", "127.0.0.1:0",
		"--health-address", occupied.Addr().String(),
	})
	if runErr == nil {
		t.Fatal("runProxy() returned nil, want health listener bind error")
	}
	if !strings.Contains(runErr.Error(), "health") {
		t.Fatalf("runProxy() error = %q, want health listener context", runErr)
	}
}
