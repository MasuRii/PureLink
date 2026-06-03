package main

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/config"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/internal/importer"
	"github.com/MasuRii/PureLink/internal/output"
	"github.com/MasuRii/PureLink/internal/speedtest"
	"github.com/MasuRii/PureLink/internal/tui"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/abuse/providers"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "dev"

var errAbuseThresholdExceeded = stderrors.New("abuse or purity threshold exceeded")

var (
	runTUI           = tui.Run
	runSpeedtest     = speedtest.Run
	checkEndpoint    = checker.CheckEndpoint
	providersByName  = providers.ByName
	providersDefault = providers.Default
)

func main() {
	root := newRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, userError(err))
		os.Exit(exitCode(err))
	}
}

type cliApp struct {
	cfg        *config.Config
	v          *viper.Viper
	out        io.Writer
	errOut     io.Writer
	configPath string
}

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	app := &cliApp{v: config.NewViper(), out: stdout, errOut: stderr}
	root := &cobra.Command{Use: "purelink", Short: "Endpoint purity and abuse scanner", Args: cobra.NoArgs, RunE: app.runDefaultTUI, PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "help" {
			return nil
		}
		return app.load(cmd)
	}}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVarP(&app.configPath, "config", "c", "", "config file path")
	root.PersistentFlags().StringP("format", "o", "table", "output format: table, json, csv, md")
	root.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	root.PersistentFlags().IntP("timeout", "t", 10, "timeout per check in seconds")
	root.PersistentFlags().Bool("no-color", false, "disable colored terminal output")
	_ = app.v.BindPFlags(root.PersistentFlags())
	_ = app.v.BindPFlag("no_color", root.PersistentFlags().Lookup("no-color"))
	root.AddCommand(app.checkCommand(), app.batchCommand(), app.dedupeCommand(), app.reportCommand(), app.importCommand(), app.speedtestCommand(), app.versionCommand(), app.configureCommand())
	return root
}

func (a *cliApp) load(cmd *cobra.Command) error {
	if err := config.ReadConfig(a.v, a.configPath); err != nil {
		return err
	}
	_ = a.v.BindPFlags(cmd.Flags())
	cfg, err := config.Load(a.v)
	if err != nil {
		return err
	}
	a.cfg = cfg
	return nil
}
func (a *cliApp) renderer() *output.Renderer {
	r := output.New(a.cfg.Format, a.out)
	r.NoColor = a.cfg.NoColor
	return r
}

func (a *cliApp) runDefaultTUI(cmd *cobra.Command, _ []string) error {
	_, err := runTUI(cmd.Context(), tui.RunOptions{
		Snapshot:   tui.Snapshot{Source: "interactive"},
		NoColor:    a.cfg.NoColor,
		Output:     a.out,
		AllowEmpty: true,
	})
	if stderrors.Is(err, tui.ErrNoTTY) || tui.IsEmptySnapshot(err) {
		return cmd.Help()
	}
	return err
}

func (a *cliApp) checkCommand() *cobra.Command {
	var abuseFlag, purityFlag, regionFlag, dnsFlag, httpFlag, failOnAbuse bool
	cmd := &cobra.Command{Use: "check <endpoint>", Short: "Validate a single endpoint", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ep, err := endpoint.Parse(args[0])
		if err != nil {
			return err
		}
		if failOnAbuse && !abuseFlag && !purityFlag {
			abuseFlag = true
		}
		res := checkEndpoint(cmd.Context(), *ep, checker.Options{DNS: dnsFlag, HTTP: httpFlag, Timeout: a.cfg.Timeout})
		providerResults := []abuse.ProviderResult{}
		if abuseFlag || purityFlag || regionFlag {
			providerResults = a.runProviders(cmd.Context(), *ep, providerNames(abuseFlag, purityFlag, regionFlag, a.cfg))
		}
		if err := a.renderer().RenderCheck(res, providerResults); err != nil {
			return err
		}
		if failOnAbuse && providerResultsRisky(providerResults) {
			return errAbuseThresholdExceeded
		}
		return nil
	}}
	cmd.Flags().BoolVar(&abuseFlag, "abuse", false, "include abuse intelligence")
	cmd.Flags().BoolVar(&purityFlag, "purity", false, "include purity signals")
	cmd.Flags().BoolVar(&regionFlag, "region", false, "include endpoint country/region lookup")
	cmd.Flags().BoolVar(&dnsFlag, "dns", false, "include DNS resolution info")
	cmd.Flags().BoolVar(&httpFlag, "http", false, "include HTTP probe")
	cmd.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
	return cmd
}

func (a *cliApp) batchCommand() *cobra.Command {
	var workers int
	var sortBy, filter, exportCleanPath, exportFormat string
	var abuseFlag, purityFlag, regionFlag, speedTestFlag, dedupeFlag, stdinFlag, interactive, noProgress, failOnAbuse bool
	cmd := &cobra.Command{Use: "batch <file|->", Short: "Validate endpoints from file or stdin", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := engine.ValidateSortMode(sortBy); err != nil {
			return err
		}
		if err := engine.ValidateFilterMode(filter); err != nil {
			return err
		}
		source := "-"
		if len(args) > 0 {
			source = args[0]
		}
		var parsed []engine.SourceEndpoint
		var err error
		if stdinFlag || source == "-" {
			parsed, err = engine.ParseReader(os.Stdin, "stdin")
		} else {
			parsed, err = engine.ParseFile(source)
		}
		if err != nil {
			return err
		}
		if dedupeFlag {
			d := engine.Dedupe(parsed)
			parsed = make([]engine.SourceEndpoint, len(d.Unique))
			for i, ep := range d.Unique {
				parsed[i] = engine.SourceEndpoint{Endpoint: ep}
			}
		}
		endpoints := make([]endpoint.Endpoint, 0, len(parsed))
		for _, item := range parsed {
			endpoints = append(endpoints, item.Endpoint)
		}
		if failOnAbuse && !abuseFlag && !purityFlag {
			abuseFlag = true
		}
		provs := []abuse.Provider{}
		if abuseFlag || purityFlag || regionFlag {
			provs = providersByName(providerNames(abuseFlag, purityFlag, regionFlag, a.cfg))
			if len(provs) == 0 {
				provs = providersDefault()
			}
		}
		if !cmd.Flags().Changed("workers") {
			workers = a.cfg.Workers
		}
		var progress, retryProgress engine.ProgressFunc
		if !noProgress && a.cfg.Format == "table" && len(endpoints) > 1 {
			progress = a.makeProgressReporter(len(endpoints))
			retryProgress = a.makeRetryProgressReporter()
		}
		be := engine.BatchEngine{Workers: workers, Timeout: a.cfg.Timeout, Providers: provs, Abuse: abuseFlag || purityFlag || regionFlag, SortBy: sortBy, Filter: filter, Progress: progress, RetryProgress: retryProgress}
		result, err := be.Run(cmd.Context(), endpoints)
		if err != nil {
			return err
		}
		if speedTestFlag {
			if speed, err := a.runOptionalSpeedtest(cmd.Context()); err == nil {
				result.Summary.SpeedMbps = speed.Mbps
			}
		}
		if exportCleanPath != "" {
			if err := exportCleanItems(exportCleanPath, exportFormat, result.Items); err != nil {
				return err
			}
		}
		if interactive {
			sourceLabel := source
			if stdinFlag || sourceLabel == "-" {
				sourceLabel = "stdin"
			}
			_, err := runTUI(cmd.Context(), tui.RunOptions{
				Snapshot:   tui.Snapshot{Items: result.Items, Summary: result.Summary, Source: sourceLabel},
				NoColor:    a.cfg.NoColor,
				Output:     a.out,
				ExportPath: exportPathOrDefault(exportCleanPath),
			})
			if err == nil {
				if failOnAbuse && batchResultRisky(*result) {
					return errAbuseThresholdExceeded
				}
				return nil
			}
			if !stderrors.Is(err, tui.ErrNoTTY) && !tui.IsEmptySnapshot(err) {
				return err
			}
		}
		if err := a.renderer().RenderBatch(*result); err != nil {
			return err
		}
		if failOnAbuse && batchResultRisky(*result) {
			return errAbuseThresholdExceeded
		}
		return nil
	}}
	cmd.Flags().IntVar(&workers, "workers", 8, "concurrent worker count")
	cmd.Flags().BoolVar(&abuseFlag, "abuse", false, "enable abuse checks")
	cmd.Flags().BoolVar(&purityFlag, "purity", false, "enable purity checks")
	cmd.Flags().BoolVar(&regionFlag, "region", false, "include endpoint country/region lookup")
	cmd.Flags().BoolVar(&speedTestFlag, "speed-test", false, "run optional free download speed test and show it in output/TUI header")
	cmd.Flags().BoolVar(&stdinFlag, "stdin", false, "read from stdin")
	cmd.Flags().BoolVar(&dedupeFlag, "dedupe", false, "deduplicate before processing")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "open interactive TUI")
	cmd.Flags().StringVar(&sortBy, "sort", "abuse", "sort results by abuse, latency, host, or port")
	cmd.Flags().StringVar(&filter, "filter", "all", "filter results: all, reachable, unreachable, abusive, suspicious, clean, errors")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable progress reporting")
	cmd.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
	cmd.Flags().StringVar(&exportCleanPath, "export-clean", "", "write clean reachable endpoints to this file")
	cmd.Flags().StringVar(&exportFormat, "export-format", "endpoints", "export format: endpoints, links/share-links, subscription/v2rayn, csv, or json")
	return cmd
}

func (a *cliApp) dedupeCommand() *cobra.Command {
	return &cobra.Command{Use: "dedupe <files...>", Short: "Find duplicates across lists", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		result, err := engine.DedupeFiles(args)
		if err != nil {
			return err
		}
		return a.renderer().RenderDedupe(result)
	}}
}

func (a *cliApp) reportCommand() *cobra.Command {
	var verbose, failOnAbuse bool
	cmd := &cobra.Command{Use: "report <endpoint>", Short: "Generate a full diagnostic report", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ep, err := endpoint.Parse(args[0])
		if err != nil {
			return err
		}
		check := checkEndpoint(cmd.Context(), *ep, checker.Options{DNS: true, HTTP: true, TLS: true, Timeout: a.cfg.Timeout})
		provs := a.runProviders(cmd.Context(), *ep, mergeProviderNames(a.cfg.Providers.Abuse, a.cfg.Providers.Purity))
		if err := a.renderer().RenderReport(check, provs, verbose); err != nil {
			return err
		}
		if failOnAbuse && providerResultsRisky(provs) {
			return errAbuseThresholdExceeded
		}
		return nil
	}}
	cmd.Flags().BoolVar(&verbose, "verbose", false, "include all available signals")
	cmd.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
	return cmd
}

func (a *cliApp) importCommand() *cobra.Command {
	var outputPath string
	var skipSecrets bool
	var interactive, abuseFlag, purityFlag, regionFlag, speedTestFlag, failOnAbuse bool
	var workers int
	var sortBy, filter, exportCleanPath, exportFormat string
	importCmd := &cobra.Command{Use: "import", Short: "Import endpoints"}
	v2cmd := &cobra.Command{Use: "v2rayn <dir>", Short: "Import from a v2rayN installation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := importer.ImportV2rayN(args[0])
		if err != nil {
			return err
		}
		if interactive {
			return a.runImportInteractive(cmd, eps, abuseFlag, purityFlag, regionFlag, speedTestFlag, workers, sortBy, filter, exportCleanPath, exportFormat, failOnAbuse, args[0])
		}
		return a.renderImportOutput(outputPath, eps, skipSecrets)
	}}
	linkCmd := &cobra.Command{Use: "link <file>", Short: "Import share links from a file", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := importer.ImportLinkFile(args[0])
		if err != nil {
			return err
		}
		if interactive {
			return a.runImportInteractive(cmd, eps, abuseFlag, purityFlag, regionFlag, speedTestFlag, workers, sortBy, filter, exportCleanPath, exportFormat, failOnAbuse, args[0])
		}
		return a.renderImportOutput(outputPath, eps, skipSecrets)
	}}
	urlCmd := &cobra.Command{Use: "url <url...>", Aliases: []string{"sub"}, Short: "Import HTTP(S) subscription URLs", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := importer.ImportSubscriptionURLs(cmd.Context(), args, importer.SubscriptionOptions{Timeout: a.cfg.Timeout})
		if err != nil {
			return err
		}
		source := fmt.Sprintf("%d subscription URL(s)", len(args))
		if interactive {
			return a.runImportInteractive(cmd, eps, abuseFlag, purityFlag, regionFlag, speedTestFlag, workers, sortBy, filter, exportCleanPath, exportFormat, failOnAbuse, source)
		}
		return a.renderImportOutput(outputPath, eps, skipSecrets)
	}}
	for _, c := range []*cobra.Command{v2cmd, linkCmd, urlCmd} {
		c.Flags().StringVarP(&outputPath, "output", "", "-", "write extracted endpoints to file or stdout")
		c.Flags().BoolVar(&skipSecrets, "skip-secrets", true, "redact credentials from output")
		c.Flags().BoolVarP(&interactive, "interactive", "i", false, "open interactive TUI")
		c.Flags().BoolVar(&abuseFlag, "abuse", false, "enable abuse checks")
		c.Flags().BoolVar(&purityFlag, "purity", false, "enable purity checks")
		c.Flags().BoolVar(&regionFlag, "region", false, "include endpoint country/region lookup")
		c.Flags().BoolVar(&speedTestFlag, "speed-test", false, "run optional free download speed test and show it in the TUI/header")
		c.Flags().IntVar(&workers, "workers", 8, "concurrent worker count")
		c.Flags().StringVar(&sortBy, "sort", "abuse", "sort results by abuse, latency, host, or port")
		c.Flags().StringVar(&filter, "filter", "all", "filter results: all, reachable, unreachable, abusive, suspicious, clean, errors")
		c.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
		c.Flags().StringVar(&exportCleanPath, "export-clean", "", "write clean reachable endpoints to this file after checks")
		c.Flags().StringVar(&exportFormat, "export-format", "endpoints", "export format: endpoints, links/share-links, subscription/v2rayn, csv, or json")
	}
	importCmd.AddCommand(v2cmd, linkCmd, urlCmd)
	return importCmd
}

func (a *cliApp) runImportInteractive(cmd *cobra.Command, eps []v2rayn.ImportedEndpoint, abuseFlag, purityFlag, regionFlag, speedTestFlag bool, workers int, sortBy, filter, exportCleanPath, exportFormat string, failOnAbuse bool, source string) error {
	metadata := metadataForImported(eps)
	endpoints := make([]endpoint.Endpoint, 0, len(eps))
	for _, ep := range eps {
		endpoints = append(endpoints, ep.ToEndpoint())
	}
	endpoints = dedupeEndpointList(endpoints)
	fmt.Fprintf(a.errOut, "Imported %d endpoints from %s\n", len(endpoints), source)
	provs := []abuse.Provider{}
	if abuseFlag || purityFlag || regionFlag {
		provs = providersByName(providerNames(abuseFlag, purityFlag, regionFlag, a.cfg))
		if len(provs) == 0 {
			provs = providersDefault()
		}
	}
	if !cmd.Flags().Changed("workers") {
		workers = a.cfg.Workers
	}
	progress := a.makeProgressReporter(len(endpoints))
	retryProgress := a.makeRetryProgressReporter()
	be := engine.BatchEngine{Workers: workers, Timeout: a.cfg.Timeout, Providers: provs, Abuse: abuseFlag || purityFlag || regionFlag, SortBy: sortBy, Filter: filter, Progress: progress, RetryProgress: retryProgress}
	result, err := be.Run(cmd.Context(), endpoints)
	if err != nil {
		return err
	}
	applyBatchMetadata(result.Items, metadata)
	if speedTestFlag {
		if speed, err := a.runOptionalSpeedtest(cmd.Context()); err == nil {
			result.Summary.SpeedMbps = speed.Mbps
		}
	}
	if exportCleanPath != "" {
		if err := exportCleanItems(exportCleanPath, exportFormat, result.Items); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.errOut, "Done — %d reachable, %d unreachable, launching TUI...\n", result.Summary.Reachable, result.Summary.Unreachable)
	_, err = runTUI(cmd.Context(), tui.RunOptions{
		Snapshot:   tui.Snapshot{Items: reachableBatchItems(result.Items), Summary: result.Summary, Source: source},
		NoColor:    a.cfg.NoColor,
		Output:     a.out,
		AllowEmpty: true,
		ExportPath: exportPathOrDefault(exportCleanPath),
	})
	if err == nil {
		if failOnAbuse && batchResultRisky(*result) {
			return errAbuseThresholdExceeded
		}
		return nil
	}
	fmt.Fprintf(a.errOut, "TUI exited: %v\n", err)
	if tui.IsEmptySnapshot(err) {
		return a.renderer().RenderBatch(*result)
	}
	if stderrors.Is(err, tui.ErrNoTTY) {
		return a.renderer().RenderBatch(*result)
	}
	return a.renderer().RenderBatch(*result)
}

type endpointMetadata struct {
	Protocol string
	RawURI   string
}

func metadataForImported(eps []v2rayn.ImportedEndpoint) map[string]endpointMetadata {
	metadata := map[string]endpointMetadata{}
	for _, imported := range eps {
		key := imported.ToEndpoint().Normalize()
		if _, exists := metadata[key]; exists {
			continue
		}
		metadata[key] = endpointMetadata{Protocol: imported.Protocol, RawURI: imported.RawURI}
	}
	return metadata
}

func applyBatchMetadata(items []engine.BatchItem, metadata map[string]endpointMetadata) {
	for i := range items {
		if meta, ok := metadata[items[i].Endpoint.Normalize()]; ok {
			items[i].Protocol = meta.Protocol
			items[i].RawURI = meta.RawURI
		}
	}
}

func dedupeEndpointList(endpoints []endpoint.Endpoint) []endpoint.Endpoint {
	seen := map[string]struct{}{}
	out := make([]endpoint.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		key := ep.Normalize()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ep)
	}
	return out
}

func reachableBatchItems(items []engine.BatchItem) []engine.BatchItem {
	out := make([]engine.BatchItem, 0, len(items))
	for _, item := range items {
		if item.Reachable {
			out = append(out, item)
		}
	}
	return out
}

func exportCleanItems(path, format string, items []engine.BatchItem) error {
	f, err := os.Create(path) // #nosec G304 -- CLI export intentionally writes to a user-specified path.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return engine.WriteExport(f, engine.CleanItems(items), format)
}

func exportPathOrDefault(path string) string {
	if strings.TrimSpace(path) == "" {
		return "PureLink-clean-endpoints.txt"
	}
	return path
}

func (a *cliApp) runOptionalSpeedtest(ctx context.Context) (speedtest.Result, error) {
	fmt.Fprintln(a.errOut, "Running optional speed test...")
	result, err := runSpeedtest(ctx, speedtest.Options{Timeout: a.cfg.Timeout})
	if err != nil {
		fmt.Fprintf(a.errOut, "Speed test skipped: %v\n", err)
		return speedtest.Result{}, err
	}
	fmt.Fprintf(a.errOut, "Speed: %s\n", speedtest.Format(result))
	return result, nil
}

func (a *cliApp) makeRetryProgressReporter() engine.ProgressFunc {
	return func(processed, total int) {
		if total <= 0 {
			return
		}
		pct := processed * 100 / total
		fmt.Fprintf(a.errOut, "Retrying timed-out providers... %d/%d (%d%%)\n", processed, total, pct)
	}
}

func (a *cliApp) makeProgressReporter(total int) engine.ProgressFunc {
	if total <= 1 {
		return nil
	}
	fmt.Fprintf(a.errOut, "Checking %d endpoints... 0/%d (0%%)\n", total, total)
	return func(processed, total int) {
		pct := 0
		if total > 0 {
			pct = processed * 100 / total
		}
		fmt.Fprintf(a.errOut, "Checking %d endpoints... %d/%d (%d%%)\n", total, processed, total, pct)
	}
}

func (a *cliApp) renderImportOutput(path string, eps []v2rayn.ImportedEndpoint, skipSecrets bool) error {
	if skipSecrets {
		eps = redactImportedEndpoints(eps)
	}
	if path == "" || path == "-" {
		return a.renderer().RenderImport(eps)
	}
	f, err := os.Create(path) // #nosec G304 -- CLI import intentionally writes to user-specified output paths.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	r := output.New(a.cfg.Format, f)
	r.NoColor = a.cfg.NoColor
	return r.RenderImport(eps)
}

func (a *cliApp) speedtestCommand() *cobra.Command {
	var url string
	var maxBytes int64
	cmd := &cobra.Command{Use: "speedtest", Short: "Run an optional free download speed test", RunE: func(cmd *cobra.Command, args []string) error {
		if url == speedtest.DefaultURL && maxBytes != speedtest.DefaultMaxByte {
			url = fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", maxBytes)
		}
		result, err := runSpeedtest(cmd.Context(), speedtest.Options{URL: url, MaxBytes: maxBytes, Timeout: a.cfg.Timeout})
		if err != nil {
			return err
		}
		if a.cfg.Format == "json" {
			enc := json.NewEncoder(a.out)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}
		fmt.Fprintf(a.out, "Speed: %s\nProvider: %s\n", speedtest.Format(result), result.URL)
		return nil
	}}
	cmd.Flags().StringVar(&url, "url", speedtest.DefaultURL, "download URL used for speed testing")
	cmd.Flags().Int64Var(&maxBytes, "bytes", speedtest.DefaultMaxByte, "maximum bytes to download")
	return cmd
}

func (a *cliApp) versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version", RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(a.out, "PureLink %s\n", version)
		return nil
	}}
}
func (a *cliApp) configureCommand() *cobra.Command {
	return &cobra.Command{Use: "configure", Short: "Show configuration guidance", RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(a.out, "Interactive configure is planned. Create ~/.purelink.yaml or use PURELINK_* environment variables.")
		return nil
	}}
}

func (a *cliApp) runProviders(ctx context.Context, ep endpoint.Endpoint, names []string) []abuse.ProviderResult {
	ip := ep.Host
	if net.ParseIP(ip) == nil {
		if addrs, err := net.DefaultResolver.LookupHost(ctx, ep.Host); err == nil && len(addrs) > 0 {
			ip = addrs[0]
		} else {
			return nil
		}
	}
	provs := providersByName(names)
	if len(provs) == 0 {
		provs = providersDefault()
	}
	out := []abuse.ProviderResult{}
	for _, p := range provs {
		cctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
		res, err := p.Check(cctx, ip)
		cancel()
		if err == nil {
			out = append(out, *abuse.NormalizeResult(p.Name(), res))
		}
	}
	return out
}

func providerNames(includeAbuse, includePurity, includeRegion bool, cfg *config.Config) []string {
	groups := [][]string{}
	if includeAbuse {
		groups = append(groups, cfg.Providers.Abuse)
	}
	if includePurity {
		groups = append(groups, cfg.Providers.Purity)
	}
	if includeRegion {
		groups = append(groups, []string{"ip-api.com", "ipapi.is"})
	}
	return mergeProviderNames(groups...)
}

func mergeProviderNames(groups ...[]string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, group := range groups {
		for _, name := range group {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

func providerResultsRisky(results []abuse.ProviderResult) bool {
	if len(results) == 0 {
		return false
	}
	merged := abuse.Merge(results)
	return riskExceeded(merged.Score, merged.Purity)
}

func batchResultRisky(result engine.BatchResult) bool {
	return result.Summary.Abusive > 0 || result.Summary.Suspicious > 0
}

func riskExceeded(score int, purity string) bool {
	if score >= 50 {
		return true
	}
	switch purity {
	case "suspicious", "vpn_likely", "vpn_detected":
		return true
	default:
		return false
	}
}

func redactImportedEndpoints(eps []v2rayn.ImportedEndpoint) []v2rayn.ImportedEndpoint {
	out := make([]v2rayn.ImportedEndpoint, len(eps))
	copy(out, eps)
	for i := range out {
		out[i].Label = v2rayn.Redact(out[i].Label)
		out[i].SubGroup = v2rayn.Redact(out[i].SubGroup)
		out[i].Source = v2rayn.Redact(out[i].Source)
		out[i].RawURI = ""
	}
	return out
}

func exitCode(err error) int {
	switch {
	case stderrors.Is(err, plerrors.ErrInvalidEndpoint), stderrors.Is(err, plerrors.ErrInvalidConfig), stderrors.Is(err, plerrors.ErrFileNotFound), stderrors.Is(err, plerrors.ErrDirectoryNotFound), stderrors.Is(err, plerrors.ErrV2rayNDBNotFound), stderrors.Is(err, plerrors.ErrV2rayNNotDetected), stderrors.Is(err, plerrors.ErrBatchEmpty):
		return 2
	case stderrors.Is(err, plerrors.ErrAllProvidersFailed), stderrors.Is(err, plerrors.ErrNetworkUnreachable):
		return 3
	case stderrors.Is(err, errAbuseThresholdExceeded):
		return 4
	default:
		return 1
	}
}
func userError(err error) string {
	msg := err.Error()
	switch {
	case stderrors.Is(err, plerrors.ErrInvalidEndpoint):
		return "error: invalid endpoint format: " + strconv.Quote(msg)
	case stderrors.Is(err, plerrors.ErrFileNotFound):
		return "error: file not found: " + strings.TrimPrefix(msg, plerrors.ErrFileNotFound.Error()+": ")
	case stderrors.Is(err, plerrors.ErrBatchEmpty):
		return "error: batch input is empty"
	case stderrors.Is(err, errAbuseThresholdExceeded):
		return "error: abuse or purity threshold exceeded"
	default:
		if strings.HasPrefix(msg, "error:") {
			return msg
		}
		return "error: " + msg
	}
}
