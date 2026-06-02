package main

import (
	"context"
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

var runTUI = tui.Run

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
	root.AddCommand(app.checkCommand(), app.batchCommand(), app.dedupeCommand(), app.reportCommand(), app.importCommand(), app.versionCommand(), app.configureCommand())
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
	return err
}

func (a *cliApp) checkCommand() *cobra.Command {
	var abuseFlag, purityFlag, dnsFlag, httpFlag, failOnAbuse bool
	cmd := &cobra.Command{Use: "check <endpoint>", Short: "Validate a single endpoint", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ep, err := endpoint.Parse(args[0])
		if err != nil {
			return err
		}
		if failOnAbuse && !abuseFlag && !purityFlag {
			abuseFlag = true
		}
		res := checker.CheckEndpoint(cmd.Context(), *ep, checker.Options{DNS: dnsFlag, HTTP: httpFlag, Timeout: a.cfg.Timeout})
		providerResults := []abuse.ProviderResult{}
		if abuseFlag || purityFlag {
			providerResults = a.runProviders(cmd.Context(), *ep, providerNames(abuseFlag, purityFlag, a.cfg))
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
	cmd.Flags().BoolVar(&dnsFlag, "dns", false, "include DNS resolution info")
	cmd.Flags().BoolVar(&httpFlag, "http", false, "include HTTP probe")
	cmd.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
	return cmd
}

func (a *cliApp) batchCommand() *cobra.Command {
	var workers int
	var sortBy, filter string
	var abuseFlag, dedupeFlag, stdinFlag, interactive, noProgress, failOnAbuse bool
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
		if failOnAbuse {
			abuseFlag = true
		}
		provs := []abuse.Provider{}
		if abuseFlag {
			provs = providers.ByName(a.cfg.Providers.Abuse)
			if len(provs) == 0 {
				provs = providers.Default()
			}
		}
		if !cmd.Flags().Changed("workers") {
			workers = a.cfg.Workers
		}
		var progress engine.ProgressFunc
		if !interactive && !noProgress && a.cfg.Format == "table" && len(endpoints) > 1 {
			fmt.Fprintf(a.errOut, "Checking %d endpoints... 0/%d (0%%)", len(endpoints), len(endpoints))
			progress = func(processed, total int) {
				pct := 0
				if total > 0 {
					pct = processed * 100 / total
				}
				fmt.Fprintf(a.errOut, "\rChecking %d endpoints... %d/%d (%d%%)", total, processed, total, pct)
				if processed == total {
					fmt.Fprintln(a.errOut)
				}
			}
		}
		be := engine.BatchEngine{Workers: workers, Timeout: a.cfg.Timeout, Providers: provs, Abuse: abuseFlag, SortBy: sortBy, Filter: filter, Progress: progress}
		result, err := be.Run(cmd.Context(), endpoints)
		if err != nil {
			return err
		}
		if interactive {
			sourceLabel := source
			if stdinFlag || sourceLabel == "-" {
				sourceLabel = "stdin"
			}
			_, err := runTUI(cmd.Context(), tui.RunOptions{
				Snapshot: tui.Snapshot{Items: result.Items, Summary: result.Summary, Source: sourceLabel},
				NoColor:  a.cfg.NoColor,
				Output:   a.out,
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
	cmd.Flags().BoolVar(&stdinFlag, "stdin", false, "read from stdin")
	cmd.Flags().BoolVar(&dedupeFlag, "dedupe", false, "deduplicate before processing")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "open interactive TUI")
	cmd.Flags().StringVar(&sortBy, "sort", "abuse", "sort results by abuse, latency, host, or port")
	cmd.Flags().StringVar(&filter, "filter", "all", "filter results: all, reachable, unreachable, abusive, suspicious, clean, errors")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable progress reporting")
	cmd.Flags().BoolVar(&failOnAbuse, "fail-on-abuse", false, "exit with code 4 when abuse or purity risk is detected")
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
		check := checker.CheckEndpoint(cmd.Context(), *ep, checker.Options{DNS: true, HTTP: true, TLS: true, Timeout: a.cfg.Timeout})
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
	importCmd := &cobra.Command{Use: "import", Short: "Import endpoints"}
	v2cmd := &cobra.Command{Use: "v2rayn <dir>", Short: "Import from a v2rayN installation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := importer.ImportV2rayN(args[0])
		if err != nil {
			return err
		}
		return a.renderImportOutput(outputPath, eps, skipSecrets)
	}}
	linkCmd := &cobra.Command{Use: "link <file>", Short: "Import share links from a file", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := importer.ImportLinkFile(args[0])
		if err != nil {
			return err
		}
		return a.renderImportOutput(outputPath, eps, skipSecrets)
	}}
	for _, c := range []*cobra.Command{v2cmd, linkCmd} {
		c.Flags().StringVarP(&outputPath, "output", "", "-", "write extracted endpoints to file or stdout")
		c.Flags().BoolVar(&skipSecrets, "skip-secrets", true, "redact credentials from output")
	}
	importCmd.AddCommand(v2cmd, linkCmd)
	return importCmd
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
	provs := providers.ByName(names)
	if len(provs) == 0 {
		provs = providers.Default()
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

func providerNames(includeAbuse, includePurity bool, cfg *config.Config) []string {
	groups := [][]string{}
	if includeAbuse {
		groups = append(groups, cfg.Providers.Abuse)
	}
	if includePurity {
		groups = append(groups, cfg.Providers.Purity)
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
