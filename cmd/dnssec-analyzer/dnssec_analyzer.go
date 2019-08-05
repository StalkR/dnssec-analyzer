// Binary dnssec_analyzer analyzes a domain with Verisign Labs DNSSEC analyzer.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/StalkR/dnssec-analyzer/dnssec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %v <domain>\n", os.Args[0])
		os.Exit(1)
	}
	domain := os.Args[1]

	analysis, err := dnssec.Analyze(domain)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(analysis)
	if analysis.Status() != dnssec.OK {
		os.Exit(1)
	}
}
