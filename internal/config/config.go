package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MasuRii/PureLink/pkg/abuse"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"github.com/spf13/viper"
)

type Config struct {
	Verbose   bool           `json:"verbose" mapstructure:"verbose"`
	Format    string         `json:"format" mapstructure:"format"`
	Timeout   time.Duration  `json:"timeout" mapstructure:"timeout"`
	Workers   int            `json:"workers" mapstructure:"workers"`
	NoColor   bool           `json:"no_color" mapstructure:"no_color"`
	Providers ProviderConfig `json:"providers" mapstructure:"providers"`
}

type ProviderConfig struct {
	Abuse  []string `json:"abuse" mapstructure:"abuse"`
	Purity []string `json:"purity" mapstructure:"purity"`
}

func Default() *Config {
	return &Config{Verbose: false, Format: "table", Timeout: 10 * time.Second, Workers: 8, NoColor: false, Providers: ProviderConfig{Abuse: []string{"blackbox", "ipapi.is", "iplogs"}, Purity: []string{"ipapi.is", "iplogs"}}}
}

func NewViper() *viper.Viper {
	v := viper.New()
	d := Default()
	v.SetDefault("verbose", d.Verbose)
	v.SetDefault("format", d.Format)
	v.SetDefault("timeout", int(d.Timeout.Seconds()))
	v.SetDefault("workers", d.Workers)
	v.SetDefault("no_color", d.NoColor)
	v.SetDefault("providers.abuse", d.Providers.Abuse)
	v.SetDefault("providers.purity", d.Providers.Purity)
	v.SetEnvPrefix("PURELINK")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()
	return v
}

func ReadConfig(v *viper.Viper, configPath string) error {
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName(".purelink")
		v.SetConfigType("yaml")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
		v.AddConfigPath(".")
	}
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok && configPath == "" {
			return nil
		}
		return fmt.Errorf("%w: %v", plerrors.ErrInvalidConfig, err)
	}
	return nil
}

func Load(v *viper.Viper) (*Config, error) {
	cfg := Default()
	cfg.Verbose = v.GetBool("verbose")
	cfg.Format = strings.ToLower(v.GetString("format"))
	cfg.Workers = v.GetInt("workers")
	cfg.NoColor = v.GetBool("no_color")
	seconds := v.GetInt("timeout")
	if seconds <= 0 && v.GetDuration("timeout") > 0 {
		cfg.Timeout = v.GetDuration("timeout")
	} else {
		cfg.Timeout = time.Duration(seconds) * time.Second
	}
	cfg.Providers.Abuse = v.GetStringSlice("providers.abuse")
	cfg.Providers.Purity = v.GetStringSlice("providers.purity")
	return cfg, Validate(cfg)
}

func Validate(c *Config) error {
	formats := map[string]struct{}{"table": {}, "json": {}, "csv": {}, "md": {}}
	if _, ok := formats[c.Format]; !ok {
		return fmt.Errorf("%w: %w", plerrors.ErrInvalidConfig, &plerrors.ValidationError{Field: "format", Value: c.Format, Message: "must be one of table, json, csv, md"})
	}
	if c.Workers < 1 || c.Workers > 256 {
		return fmt.Errorf("%w: %w", plerrors.ErrInvalidConfig, &plerrors.ValidationError{Field: "workers", Value: c.Workers, Message: "must be between 1 and 256"})
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return fmt.Errorf("%w: %w", plerrors.ErrInvalidConfig, &plerrors.ValidationError{Field: "timeout", Value: c.Timeout, Message: "must be between 1s and 5m"})
	}
	for _, name := range append(append([]string{}, c.Providers.Abuse...), c.Providers.Purity...) {
		if _, ok := abuse.KnownProviderNames[name]; !ok {
			return fmt.Errorf("%w: %w", plerrors.ErrInvalidConfig, &plerrors.ValidationError{Field: "providers", Value: name, Message: "unknown provider"})
		}
	}
	return nil
}
