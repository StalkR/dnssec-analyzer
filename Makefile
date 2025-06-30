all:
	go build $$PWD/cmd/dnssec-analyzer
	go build $$PWD/cmd/dnssec-monitor
install:
	mkdir -p $(DESTDIR)/usr/bin
	cp dnssec-analyzer $(DESTDIR)/usr/bin
	cp dnssec-monitor $(DESTDIR)/usr/bin
	chmod 755 $(DESTDIR)/usr/bin/dnssec-analyzer
	chmod 755 $(DESTDIR)/usr/bin/dnssec-monitor
clean:
	rm -f dnssec-analyzer
	rm -f dnssec-monitor
