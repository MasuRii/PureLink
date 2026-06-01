package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/MasuRii/PureLink/pkg/endpoint"
)

type CheckResult struct {
	Endpoint   endpoint.Endpoint `json:"endpoint"`
	Reachable  bool              `json:"reachable"`
	LatencyMs  int64             `json:"latency_ms"`
	Error      string            `json:"error,omitempty"`
	TLSVersion string            `json:"tls_version,omitempty"`
	TLSCipher  string            `json:"tls_cipher,omitempty"`
	HTTPStatus int               `json:"http_status,omitempty"`
	DNSAddrs   []string          `json:"dns_addrs,omitempty"`
}

type Options struct {
	DNS     bool
	HTTP    bool
	TLS     bool
	Timeout time.Duration
}

// Legacy Result holds the validation outcome for an endpoint.
type Result struct {
	Address   string
	Reachable bool
	Abused    bool
	Pure      bool
	Latency   int64
}

// Check performs a backward-compatible TCP connectivity check.
func Check(address string) (*Result, error) {
	ep, err := endpoint.Parse(address)
	if err != nil {
		return nil, err
	}
	res := CheckEndpoint(context.Background(), *ep, Options{Timeout: 10 * time.Second})
	return &Result{Address: address, Reachable: res.Reachable, Latency: res.LatencyMs}, nil
}

func CheckEndpoint(ctx context.Context, ep endpoint.Endpoint, opts Options) CheckResult {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	res := CheckResult{Endpoint: ep}
	if opts.DNS {
		if addrs, err := net.DefaultResolver.LookupHost(ctx, ep.Host); err == nil {
			res.DNSAddrs = addrs
		}
	}
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Reachable = true
	_ = conn.Close()

	if opts.TLS || ep.Port == 443 {
		if tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", addr, &tls.Config{ServerName: ep.Host, MinVersion: tls.VersionTLS12}); err == nil {
			state := tlsConn.ConnectionState()
			res.TLSVersion = tlsVersion(state.Version)
			res.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
			_ = tlsConn.Close()
		}
	}
	if opts.HTTP {
		client := http.Client{Timeout: opts.Timeout}
		scheme := "http"
		if ep.Port == 443 {
			scheme = "https"
		}
		if resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, addr)); err == nil {
			res.HTTPStatus = resp.StatusCode
			_ = resp.Body.Close()
		}
	}
	return res
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("0x%x", v)
	}
}
