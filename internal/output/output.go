package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// Printer handles formatted output.
type Printer struct {
	Format string
}

// New creates a Printer for the given format.
func New(format string) *Printer {
	return &Printer{Format: format}
}

// PrintJSON marshals and prints data as JSON.
func (p *Printer) PrintJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintTable prints a simple table header.
func (p *Printer) PrintTable(headers []string) {
	for _, h := range headers {
		fmt.Printf("%-20s", h)
	}
	fmt.Println()
}
