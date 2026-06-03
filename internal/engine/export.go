package engine

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func CleanItems(items []BatchItem) []BatchItem {
	out := make([]BatchItem, 0, len(items))
	for _, item := range items {
		if IsCleanItem(item) {
			out = append(out, item)
		}
	}
	return out
}

func IsCleanItem(item BatchItem) bool {
	if !item.Reachable || item.AbuseScore >= 50 || item.Purity != "clean" {
		return false
	}
	// ProviderErrs can contain final warnings for providers that timed out even
	// after retry. If at least one provider succeeded and the merged verdict is
	// clean, the endpoint should still be exportable; otherwise one slow provider
	// would incorrectly block every clean export.
	if item.ProviderTotal > 0 && item.ProviderSuccesses == 0 {
		return false
	}
	return true
}

type ExportFile struct {
	Group string
	Path  string
	Count int
}

type SplitExportResult struct {
	Directory string
	Count     int
	Files     []ExportFile
}

func WriteExport(w io.Writer, items []BatchItem, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "endpoints", "proxy-pool", "proxy_pool", "txt":
		for _, item := range items {
			if _, err := fmt.Fprintln(w, item.Endpoint.Normalize()); err != nil {
				return err
			}
		}
		return nil
	case "share-links", "share_links", "links":
		links := preservedShareLinks(items)
		if len(links) == 0 {
			return fmt.Errorf("no preserved share links available for export")
		}
		for _, link := range links {
			if _, err := fmt.Fprintln(w, link); err != nil {
				return err
			}
		}
		return nil
	case "subscription", "v2rayn", "v2rayn-subscription", "v2rayn_subscription":
		links := preservedShareLinks(items)
		if len(links) == 0 {
			return fmt.Errorf("no preserved share links available for export")
		}
		_, err := fmt.Fprintln(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
		return err
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"protocol", "host", "port", "country", "country_code", "abuse_score", "purity"})
		for _, item := range items {
			_ = cw.Write([]string{item.Protocol, item.Endpoint.Host, strconv.Itoa(item.Endpoint.Port), item.Country, item.CountryCode, strconv.Itoa(item.AbuseScore), item.Purity})
		}
		cw.Flush()
		return cw.Error()
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func preservedShareLinks(items []BatchItem) []string {
	links := make([]string, 0, len(items))
	for _, item := range items {
		if link := strings.TrimSpace(item.RawURI); link != "" {
			links = append(links, link)
		}
	}
	return links
}

func WriteSplitExport(directory string, items []BatchItem, groupBy string, format string) (SplitExportResult, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		directory = "PureLink-export"
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return SplitExportResult{}, err
	}

	groups, labels := groupItems(items, groupBy)
	result := SplitExportResult{Directory: directory, Count: len(items)}
	for _, label := range labels {
		groupItems := groups[label]
		path := filepath.Join(directory, splitExportFileName(groupBy, label, format))
		file, err := os.Create(path) // #nosec G304 -- export path is intentionally user-controlled.
		if err != nil {
			return SplitExportResult{}, err
		}
		if err := WriteExport(file, groupItems, format); err != nil {
			_ = file.Close()
			return SplitExportResult{}, err
		}
		if err := file.Close(); err != nil {
			return SplitExportResult{}, err
		}
		result.Files = append(result.Files, ExportFile{Group: label, Path: path, Count: len(groupItems)})
	}
	if err := writeSplitExportSummary(directory, groupBy, result.Files, len(items)); err != nil {
		return SplitExportResult{}, err
	}
	return result, nil
}

func groupItems(items []BatchItem, groupBy string) (map[string][]BatchItem, []string) {
	groups := map[string][]BatchItem{}
	for _, item := range items {
		label := exportGroupLabel(item, groupBy)
		groups[label] = append(groups[label], item)
	}
	labels := make([]string, 0, len(groups))
	for label := range groups {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return groups, labels
}

func exportGroupLabel(item BatchItem, groupBy string) string {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "region", "country":
		if strings.TrimSpace(item.Country) != "" {
			return strings.TrimSpace(item.Country)
		}
		if strings.TrimSpace(item.CountryCode) != "" {
			return strings.ToUpper(strings.TrimSpace(item.CountryCode))
		}
		return "Unknown Region"
	case "protocol", "proto":
		if strings.TrimSpace(item.Protocol) != "" {
			return strings.TrimSpace(item.Protocol)
		}
		return "Unknown Protocol"
	default:
		return "All"
	}
}

func splitExportFileName(groupBy, label, format string) string {
	prefix := "PureLink"
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "region", "country":
		prefix += "-region"
	case "protocol", "proto":
		prefix += "-protocol"
	default:
		prefix += "-export"
	}
	return fmt.Sprintf("%s-%s.%s", prefix, slugifyExportLabel(label), exportExtension(format))
}

func exportExtension(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "csv":
		return "csv"
	case "json":
		return "json"
	default:
		return "txt"
	}
}

var exportSlugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

func slugifyExportLabel(label string) string {
	slug := strings.ToLower(strings.TrimSpace(label))
	slug = exportSlugInvalid.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "unknown"
	}
	return slug
}

func writeSplitExportSummary(directory, groupBy string, files []ExportFile, total int) error {
	path := filepath.Join(directory, "PureLink-export-summary.txt")
	file, err := os.Create(path) // #nosec G304 -- export path is intentionally user-controlled.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	fmt.Fprintln(file, "PureLink Export Summary")
	fmt.Fprintf(file, "Grouped by: %s\n", displayGroupBy(groupBy))
	fmt.Fprintf(file, "Total endpoints: %d\n\n", total)
	for _, exported := range files {
		fmt.Fprintf(file, "- %s: %d endpoints -> %s\n", exported.Group, exported.Count, filepath.Base(exported.Path))
	}
	return nil
}

func displayGroupBy(groupBy string) string {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "region", "country":
		return "region"
	case "protocol", "proto":
		return "protocol"
	default:
		return "all"
	}
}
