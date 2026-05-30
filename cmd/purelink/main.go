package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "purelink: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("PureLink %s — endpoint purity and abuse scanner\n\n", version)
	fmt.Println("Usage:")
	fmt.Println("  purelink check  <endpoint>    Validate a single endpoint")
	fmt.Println("  purelink batch  <file>        Validate endpoints from file")
	fmt.Println("  purelink dedupe <files...>    Find duplicates across lists")
	fmt.Println("  purelink report <endpoint>    Full diagnostic report")
	fmt.Println("  purelink version              Print version")
	fmt.Println("\nRun 'purelink --help' for full documentation.")
	return nil
}
