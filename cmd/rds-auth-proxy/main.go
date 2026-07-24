package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"

	proxyserver "github.com/example/rds-auth-proxy/internal/proxy"
)

const usage = `Usage:
  rds-auth-proxy proxy --endpoint HOST:PORT --region REGION [--listen HOST:PORT]
  rds-auth-proxy token --endpoint HOST:PORT --region REGION --user USER

The proxy accepts local plaintext PostgreSQL connections, establishes verified
TLS to RDS, and injects a fresh IAM authentication token for each connection.`

type iamTokenProvider struct {
	endpoint, region string
	credentials      aws.CredentialsProvider
}

func (p iamTokenProvider) Token(ctx context.Context, user string) (string, error) {
	token, err := auth.BuildAuthToken(ctx, p.endpoint, p.region, user, p.credentials)
	if err != nil {
		return "", err
	}
	return withExplicitRootPath(token), nil
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(parent context.Context, arguments []string) error {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return errors.New("a command is required")
	}
	switch arguments[0] {
	case "proxy":
		return runProxy(parent, arguments[1:])
	case "token":
		return runToken(parent, arguments[1:])
	case "help", "-h", "--help":
		fmt.Println(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func runProxy(parent context.Context, arguments []string) error {
	flags := flag.NewFlagSet("proxy", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "", "RDS or Aurora endpoint as host:port")
	listenAddress := flags.String("listen", "127.0.0.1:5432", "local listen address")
	healthAddress := flags.String("health-address", "127.0.0.1:9090", "HTTP health listen address (empty disables)")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	region := flags.String("region", "", "AWS region")
	rootCA := flags.String("root-ca", "", "PEM CA bundle for verifying the RDS server (default: system roots)")
	tlsNegotiation := flags.String("tls-negotiation", "postgres", "upstream TLS negotiation: postgres or direct")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if *endpoint == "" || *region == "" {
		return errors.New("endpoint and region are required")
	}
	if *tlsNegotiation != "postgres" && *tlsNegotiation != "direct" {
		return errors.New("tls-negotiation must be postgres or direct")
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(parent, awsconfig.WithRegion(*region))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	tlsConfig, err := upstreamTLSConfig(*endpoint, *rootCA)
	if err != nil {
		return err
	}
	proxy, err := proxyserver.New(proxyserver.Config{
		ListenAddress: *listenAddress, Endpoint: *endpoint, DialTimeout: *dialTimeout,
		TLSConfig:     tlsConfig,
		DirectTLS:     *tlsNegotiation == "direct",
		TokenProvider: iamTokenProvider{endpoint: *endpoint, region: *region, credentials: awsConfig.Credentials},
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddress, err)
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *healthAddress == "" {
		slog.Info("proxy listening", "listen", listener.Addr(), "endpoint", *endpoint)
		return proxy.Serve(ctx, listener)
	}

	healthListener, err := net.Listen("tcp", *healthAddress)
	if err != nil {
		return fmt.Errorf("listen for health checks on %s: %w", *healthAddress, err)
	}
	defer healthListener.Close()

	server := &http.Server{Handler: healthHandler(), ReadHeaderTimeout: 2 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	healthErrors := make(chan error, 1)
	go func() {
		if serveErr := server.Serve(healthListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			healthErrors <- serveErr
		}
	}()

	proxyErrors := make(chan error, 1)
	go func() {
		proxyErrors <- proxy.Serve(ctx, listener)
	}()
	slog.Info("proxy listening", "listen", listener.Addr(), "endpoint", *endpoint)
	select {
	case proxyErr := <-proxyErrors:
		return proxyErr
	case healthErr := <-healthErrors:
		stop()
		<-proxyErrors
		return fmt.Errorf("serve health checks on %s: %w", *healthAddress, healthErr)
	}
}

func runToken(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "", "RDS or Aurora endpoint as host:port")
	region := flags.String("region", "", "AWS region")
	user := flags.String("user", "", "database user configured for IAM authentication")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *endpoint == "" || *region == "" || *user == "" {
		return errors.New("endpoint, region, and user are required")
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(*region))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	token, err := auth.BuildAuthToken(ctx, *endpoint, *region, *user, awsConfig.Credentials)
	if err != nil {
		return fmt.Errorf("build authentication token: %w", err)
	}
	fmt.Println(withExplicitRootPath(token))
	return nil
}

func upstreamTLSConfig(endpoint, rootCAPath string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid RDS endpoint: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if rootCAPath == "" {
		return config, nil
	}
	pem, err := os.ReadFile(rootCAPath)
	if err != nil {
		return nil, fmt.Errorf("read root CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("root CA bundle contains no certificates")
	}
	config.RootCAs = roots
	return config, nil
}

func withExplicitRootPath(token string) string {
	queryStart := strings.IndexByte(token, '?')
	if queryStart <= 0 || token[queryStart-1] == '/' {
		return token
	}
	return token[:queryStart] + "/" + token[queryStart:]
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
	})
	return mux
}
