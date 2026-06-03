package engine

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func TestIsCleanItemAllowsPartialProviderWarnings(t *testing.T) {
	item := BatchItem{
		Endpoint:          endpoint.Endpoint{Host: "192.0.2.1", Port: 443},
		Reachable:         true,
		AbuseScore:        0,
		Purity:            "clean",
		ProviderTotal:     3,
		ProviderSuccesses: 1,
		ProviderErrs:      []string{"iplogs: timeout after retry"},
	}
	if !IsCleanItem(item) {
		t.Fatalf("expected partial provider warnings to remain exportable clean: %+v", item)
	}
}

func TestWriteExportShareLinksAndSubscription(t *testing.T) {
	items := []BatchItem{
		{Endpoint: endpoint.Endpoint{Host: "192.0.2.1", Port: 443}, RawURI: "vless://placeholder@192.0.2.1:443#one"},
		{Endpoint: endpoint.Endpoint{Host: "192.0.2.2", Port: 443}},
		{Endpoint: endpoint.Endpoint{Host: "192.0.2.3", Port: 443}, RawURI: "trojan://credential@192.0.2.3:443#two"},
	}
	var links bytes.Buffer
	if err := WriteExport(&links, items, "links"); err != nil {
		t.Fatal(err)
	}
	if got := links.String(); got != "vless://placeholder@192.0.2.1:443#one\ntrojan://credential@192.0.2.3:443#two\n" {
		t.Fatalf("unexpected links export: %q", got)
	}

	var sub bytes.Buffer
	if err := WriteExport(&sub, items, "v2rayn"); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sub.String()))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != strings.TrimSuffix(links.String(), "\n") {
		t.Fatalf("unexpected subscription payload: %q", decoded)
	}
}

func TestWriteExportShareLinksRequiresPreservedRawURI(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, []BatchItem{{Endpoint: endpoint.Endpoint{Host: "192.0.2.1", Port: 443}}}, "share-links")
	if err == nil || !strings.Contains(err.Error(), "no preserved share links") {
		t.Fatalf("expected clear missing raw URI error, got %v", err)
	}
}

func TestIsCleanItemRejectsNoSuccessfulProviderData(t *testing.T) {
	item := BatchItem{
		Endpoint:          endpoint.Endpoint{Host: "192.0.2.1", Port: 443},
		Reachable:         true,
		AbuseScore:        0,
		Purity:            "clean",
		ProviderTotal:     3,
		ProviderSuccesses: 0,
		ProviderErrs:      []string{"ipapi.is: timeout after retry"},
	}
	if IsCleanItem(item) {
		t.Fatalf("expected no-provider-success item to be rejected: %+v", item)
	}
}
