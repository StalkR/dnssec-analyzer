// Binary dnssec_monitor monitors domains with Verisign Labs DNSSEC analyzer.
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
	flagDomains  = flag.String("domains", "", "Domain names to check (comma-separated list).")
	flagDuration = flag.Duration("every", 24*time.Hour, "Check every duration.")
	flagFrom     = flag.String("from", "", "Email sender.")
	flagTo       = flag.String("to", "", "Email recipient.")
)

func main() {
	flag.Parse()
	domains := strings.Split(*flagDomains, ",")
	if len(domains) == 0 || *flagFrom == "" || *flagTo == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	for _, domain := range domains {
		monitor(domain)
	}
}

func monitor(domain string) {
	s := &monitorState{current: dnssec.OK}
	for ; ; time.Sleep(*flagDuration) {
		before := s.State()
		var result dnssec.Status
		var details string
		analysis, err := dnssec.Analyze(domain)
		if err != nil {
			log.Printf("[%v] (state %v) error: %v", domain, before, err)
			result = dnssec.WARNING
			details = err.Error()
		} else {
			log.Printf("[%v] (state %v) status: %v", domain, before, analysis.Status())
			result = analysis.Status()
			details = analysis.String()
		}

		after := s.Transition(result)
		if before == after {
			continue
		}
		if before == dnssec.ERROR || after == dnssec.ERROR {
			log.Printf("[%v] (state %v) new state: %v", domain, before, after)
			if err := email(domain, after.String(), details); err != nil {
				log.Printf("[%v] email error: %v", domain, err)
			}
		}
	}
}

type monitorState struct {
	current  dnssec.Status
	warnings int
}

func (s *monitorState) State() dnssec.Status {
	return s.current
}

// Transition operates the monitor state machine: OK, WARNING, ERROR.
// 3 consecutive warnings, we transition to ERROR.
// Transitions in or out of ERROR generate an alert.
//                  +----> OK <--+
//                  |            |
//                  v            v
//              WARNING ------> ERROR
func (s *monitorState) Transition(result dnssec.Status) dnssec.Status {
	switch s.current {
	case dnssec.OK:
		s.current = result

	case dnssec.WARNING:
		switch result {
		case dnssec.OK:
			s.warnings = 0
			s.current = dnssec.OK
		case dnssec.WARNING:
			s.warnings++
			if s.warnings > 3 {
				s.warnings = 0
				s.current = dnssec.ERROR
			}
		case dnssec.ERROR:
			s.warnings = 0
			s.current = dnssec.ERROR
		}

	case dnssec.ERROR:
		switch result {
		case dnssec.OK:
			s.current = dnssec.OK
		}
	}

	return s.current
}

func email(domain, state, details string) error {
	subject := fmt.Sprintf("DNSSEC monitor for %v: %v", domain, state)
	body := fmt.Sprintf("%s%s\n%s", dnssec.URL, domain, details)
	return mail(*flagFrom, *flagTo, subject, body)
}

func mail(from, to, subject, body string) error {
	cmd := exec.Command("/usr/sbin/sendmail", "-t")
	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", from, to, subject, body)
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("err: %v; out: %q", err, out)
	}
	return nil
}
