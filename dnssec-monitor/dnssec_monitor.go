// Binary dnssec_monitor monitors a domain with Verisign Labs DNSSEC analyzer.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/StalkR/dnssec-analyzer/dnssec"
)

var (
	flagDomain   = flag.String("domain", "", "Domain name to check.")
	flagDuration = flag.Duration("every", 24*time.Hour, "Check every duration.")
	flagFrom     = flag.String("from", "", "Email sender.")
	flagTo       = flag.String("to", "", "Email recipient.")
)

func main() {
	flag.Parse()
	if *flagDomain == "" || *flagFrom == "" || *flagTo == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	var state dnssec.Status
	var warnings int
	for ; ; time.Sleep(*flagDuration) {
		var result dnssec.Status
		var details string
		analysis, err := dnssec.Analyze(*flagDomain)
		if err != nil {
			log.Printf("[Analyze (%s)] Error: %v", state, err)
			result = dnssec.WARNING
			details = err.Error()
		} else {
			log.Printf("[Analyze (%s)] Status: %s", state, analysis.Status())
			result = analysis.Status()
			details = analysis.String()
		}

		/*
			State machine:   +----> OK <--+
			                 |            |
			                 v            v
			             WARNING ------> ERROR
			- 3 consecutive warnings, we transition to ERROR.
			- transitions in or out of error state generates an alert
		*/
		var newState dnssec.Status
		switch state {
		case dnssec.OK:
			switch result {
			case dnssec.WARNING:
				newState = dnssec.WARNING
			case dnssec.ERROR:
				newState = dnssec.ERROR
			}

		case dnssec.WARNING:
			switch result {
			case dnssec.OK:
				newState = dnssec.OK
				warnings = 0
			case dnssec.WARNING:
				warnings++
				if warnings > 3 {
					newState = dnssec.ERROR
					warnings = 0
				}
			case dnssec.ERROR:
				newState = dnssec.ERROR
				warnings = 0
			}

		case dnssec.ERROR:
			switch result {
			case dnssec.OK:
				newState = dnssec.OK
			}
		}

		if state == newState {
			continue
		}
		if state == dnssec.ERROR || newState == dnssec.ERROR {
			log.Printf("[Analyze (%s)] New state: %s", state, newState)
			if err := email(newState.String(), details); err != nil {
				log.Print(err)
			}
		}
		state = newState
	}
}

func email(state, body string) error {
	subject := fmt.Sprintf("DNSSEC monitor: %s [%s]", *flagDomain, state)
	return mail(*flagFrom, *flagTo, subject, body)
}

func mail(from, to, subject, body string) error {
	cmd := exec.Command("/usr/sbin/sendmail", "-t")
	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", from, to, subject, body)
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mail error: %v; out: %q", err, out)
	}
	return nil
}
