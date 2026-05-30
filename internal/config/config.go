package config

// Config holds runtime configuration for PureLink.
type Config struct {
	Verbose bool
	Format  string // table, json, csv, md
	Timeout int    // seconds
}

// Default returns a sensible default configuration.
func Default() *Config {
	return &Config{
		Verbose: false,
		Format:  "table",
		Timeout: 10,
	}
}
