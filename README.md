# DNSSEC analyzer

[![Build Status](https://github.com/StalkR/dnssec-analyzer/actions/workflows/build.yml/badge.svg)](https://github.com/StalkR/dnssec-analyzer/actions/workflows/build.yml) [![Godoc](https://godoc.org/github.com/StalkR/dnssec-analyzer?status.png)](https://godoc.org/github.com/StalkR/dnssec-analyzer)

A Go library and command-line tools to use Verisign Labs DNSSEC analyzer:
https://dnssec-analyzer.verisignlabs.com

# Command-line tools

## dnssec-analyzer

Source: https://github.com/StalkR/dnssec-analyzer/blob/master/cmd/dnssec-analyzer

It lets you query the web interface from command-line:

    $ go get github.com/StalkR/dnssec-analyzer
    $ go build github.com/StalkR/dnssec-analyzer/cmd/dnssec-analyzer
    $ ./dnssec-analyzer stalkr.net
    # .
    OK: Found 2 DNSKEY records for .
    OK: DS=20326/SHA-256 verifies DNSKEY=20326/SEP
    OK: Found 1 RRSIGs over DNSKEY RRset
    OK: RRSIG=20326 and DNSKEY=20326/SEP verifies the DNSKEY RRset
    # net
    OK: Found 1 DS records for net in the . zone
    OK: DS=35886/SHA-256 has algorithm RSASHA256
    OK: Found 1 RRSIGs over DS RRset
    OK: RRSIG=59944 and DNSKEY=59944 verifies the DS RRset
    OK: Found 3 DNSKEY records for net
    OK: DS=35886/SHA-256 verifies DNSKEY=35886/SEP
    OK: Found 1 RRSIGs over DNSKEY RRset
    OK: RRSIG=35886 and DNSKEY=35886/SEP verifies the DNSKEY RRset
    # stalkr.net
    OK: Found 1 DS records for stalkr.net in the net zone
    OK: DS=1363/SHA-256 has algorithm ECDSAP256SHA256
    OK: Found 1 RRSIGs over DS RRset
    OK: RRSIG=59540 and DNSKEY=59540 verifies the DS RRset
    OK: Found 1 DNSKEY records for stalkr.net
    OK: DS=1363/SHA-256 verifies DNSKEY=1363/SEP
    OK: Found 1 RRSIGs over DNSKEY RRset
    OK: RRSIG=1363 and DNSKEY=1363/SEP verifies the DNSKEY RRset
    OK: stalkr.net A RR has value 51.38.54.48
    OK: Found 1 RRSIGs over A RRset
    OK: RRSIG=1363 and DNSKEY=1363/SEP verifies the A RRset

## dnssec-monitor

Source: https://github.com/StalkR/dnssec-analyzer/blob/master/cmd/dnssec-monitor

It lets your monitor domains for their DNSSEC status regularly
(default 24h) and send email alerts (using `sendmail`) when there are errors
or warnings 3 times in a row:

    $ go get github.com/StalkR/dnssec-analyzer
    $ go build github.com/StalkR/dnssec-analyzer/cmd/dnssec-monitor
    $ ./dnssec-monitor -domains stalkr.net -from <email> -to <email> -every 24h
    ...

Alternatively, create the Debian package and install it:

    $ cd $GOPATH/src/github.com/StalkR/dnssec-analyzer/cmd/dnssec-monitor
    $ fakeroot debian/rules clean binary
    $ sudo dpkg -i ../dnssec-monitor_1-1_amd64.deb

Configure in `/etc/default/dnssec-monitor` and start with `/etc/init.d/dnssec-monitor start`.

# License

[Apache License, version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

# Thanks

Verisign Labs for their powerful, stable and longtime supported DNSSEC analyzer.

# Bugs, feature requests, questions

Create a [new issue](https://github.com/StalkR/dnssec-analyzer/issues/new).
