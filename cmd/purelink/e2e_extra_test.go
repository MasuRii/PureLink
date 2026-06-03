package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/speedtest"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

type cliFakeProvider struct{ result abuse.ProviderResult }

func (p cliFakeProvider) Name() string { return "fake-provider" }
func (p cliFakeProvider) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 1000, Burst: 1}
}
func (p cliFakeProvider) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	return &p.result, nil
}

func withCLIFakes(t *testing.T) {
	t.Helper()
	oldCheck := checkEndpoint
	oldSpeed := runSpeedtest
	oldByName := providersByName
	oldDefault := providersDefault
	checkEndpoint = func(ctx context.Context, ep endpoint.Endpoint, opts checker.Options) checker.CheckResult {
		return checker.CheckResult{Endpoint: ep, Reachable: true, LatencyMs: 3, DNSAddrs: []string{"127.0.0.1"}, TLSVersion: "TLS1.3", TLSCipher: "TLS_AES_128_GCM_SHA256", HTTPStatus: 204}
	}
	runSpeedtest = func(ctx context.Context, opts speedtest.Options) (speedtest.Result, error) {
		return speedtest.Result{URL: opts.URL, Bytes: 1_000_000, Duration: time.Second, Mbps: 8}, nil
	}
	fakeProviders := []abuse.Provider{cliFakeProvider{result: abuse.ProviderResult{Score: 0, Confidence: 1, Purity: "clean", Country: "Local", CountryCode: "LO"}}}
	providersByName = func(names []string) []abuse.Provider { return fakeProviders }
	providersDefault = func() []abuse.Provider { return fakeProviders }
	t.Cleanup(func() {
		checkEndpoint = oldCheck
		runSpeedtest = oldSpeed
		providersByName = oldByName
		providersDefault = oldDefault
	})
}

func TestCheckCommandDeterministicWithFakeProvider(t *testing.T) {
	withCLIFakes(t)
	out, _, err := execute("--format", "json", "check", "example.com:443", "--abuse", "--dns", "--http")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fake-provider") || !strings.Contains(out, "\"reachable\": true") || !strings.Contains(out, "Local") {
		t.Fatalf("unexpected check output: %s", out)
	}
}

func TestReportCommandFailOnAbuseUsesFakeProvider(t *testing.T) {
	withCLIFakes(t)
	providersByName = func(names []string) []abuse.Provider {
		return []abuse.Provider{cliFakeProvider{result: abuse.ProviderResult{Score: 80, Confidence: 1, Purity: "vpn_detected"}}}
	}
	_, _, err := execute("--format", "json", "report", "example.com:443", "--fail-on-abuse")
	if err == nil || exitCode(err) != 4 {
		t.Fatalf("expected abuse threshold exit, got err=%v code=%d", err, exitCode(err))
	}
}

func TestSpeedtestCommandJSONUsesInjectedRunner(t *testing.T) {
	withCLIFakes(t)
	out, _, err := execute("--format", "json", "speedtest", "--url", "http://127.0.0.1/speed", "--bytes", "123")
	if err != nil {
		t.Fatal(err)
	}
	var result speedtest.Result
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json %q: %v", out, err)
	}
	if result.URL != "http://127.0.0.1/speed" || result.Mbps != 8 {
		t.Fatalf("unexpected speedtest result: %+v", result)
	}
}

func TestCheckCommandAgainstLocalListenerE2E(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	out, _, err := execute("--timeout", "1", "--format", "json", "check", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\"reachable\": true") {
		t.Fatalf("expected reachable local listener output, got %s", out)
	}
	<-done
}

func TestUserErrorMappings(t *testing.T) {
	cases := []struct {
		err  error
		want string
		code int
	}{
		{plerrors.ErrBatchEmpty, "batch input is empty", 2},
		{plerrors.ErrFileNotFound, "file not found", 2},
		{plerrors.ErrInvalidEndpoint, "invalid endpoint format", 2},
	}
	for _, tc := range cases {
		if got := userError(tc.err); !strings.Contains(got, tc.want) {
			t.Fatalf("userError(%v)=%q", tc.err, got)
		}
		if got := exitCode(tc.err); got != tc.code {
			t.Fatalf("exitCode(%v)=%d, want %d", tc.err, got, tc.code)
		}
	}
}
