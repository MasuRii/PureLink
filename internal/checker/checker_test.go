package checker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func startTCPListener(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func generateTestCert(t *testing.T) tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCheck_InvalidEndpoint(t *testing.T) {
	_, err := Check("")
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestCheck_ValidEndpoint(t *testing.T) {
	l := startTCPListener(t)
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	res, err := Check(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable {
		t.Fatal("expected reachable")
	}
	if res.Latency < 0 {
		t.Fatalf("unexpected negative latency: %d", res.Latency)
	}
}

func TestCheckEndpoint_DefaultTimeout(t *testing.T) {
	l := startTCPListener(t)
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ep := endpoint.Endpoint{Host: "127.0.0.1", Port: port}
	res := CheckEndpoint(context.Background(), ep, Options{})
	if !res.Reachable {
		t.Fatal("expected reachable with default timeout")
	}
}

func TestCheckEndpoint_TCPReachable(t *testing.T) {
	l := startTCPListener(t)
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ep := endpoint.Endpoint{Host: "127.0.0.1", Port: port}
	res := CheckEndpoint(context.Background(), ep, Options{Timeout: 2 * time.Second})
	if !res.Reachable {
		t.Fatal("expected reachable")
	}
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
}

func TestCheckEndpoint_TCPUnreachable(t *testing.T) {
	l := startTCPListener(t)
	_ = l.Close() // immediately close
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ep := endpoint.Endpoint{Host: "127.0.0.1", Port: port}
	res := CheckEndpoint(context.Background(), ep, Options{Timeout: 500 * time.Millisecond})
	if res.Reachable {
		t.Fatal("expected unreachable")
	}
	if res.Error == "" {
		t.Fatal("expected error for unreachable endpoint")
	}
}

func TestCheckEndpoint_DNS(t *testing.T) {
	ep := endpoint.Endpoint{Host: "localhost", Port: 80}
	res := CheckEndpoint(context.Background(), ep, Options{DNS: true, Timeout: 2 * time.Second})
	found := false
	for _, a := range res.DNSAddrs {
		if a == "127.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 127.0.0.1 in DNSAddrs, got %v", res.DNSAddrs)
	}
}

func TestCheckEndpoint_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ep := endpoint.Endpoint{Host: host, Port: port}
	res := CheckEndpoint(context.Background(), ep, Options{HTTP: true, Timeout: 2 * time.Second})
	if res.HTTPStatus != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.HTTPStatus)
	}
}

func TestCheckEndpoint_TLS_FailureSelfSigned(t *testing.T) {
	cert := generateTestCert(t)
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ep := endpoint.Endpoint{Host: "127.0.0.1", Port: port}
	res := CheckEndpoint(context.Background(), ep, Options{TLS: true, Timeout: 2 * time.Second})
	if !res.Reachable {
		t.Fatal("expected TCP reachable")
	}
	if res.TLSVersion != "" {
		t.Fatalf("expected empty TLSVersion when handshake fails, got %q", res.TLSVersion)
	}
	if res.TLSCipher != "" {
		t.Fatalf("expected empty TLSCipher when handshake fails, got %q", res.TLSCipher)
	}
}

func TestTLSVersion(t *testing.T) {
	tests := []struct {
		input    uint16
		expected string
	}{
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0, ""},
		{0x0301, "0x301"},
	}
	for _, tt := range tests {
		got := tlsVersion(tt.input)
		if got != tt.expected {
			t.Fatalf("tlsVersion(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
