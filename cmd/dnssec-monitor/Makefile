all:
	go build .
install:
	mkdir -p $(DESTDIR)/usr/bin
	cp dnssec-monitor $(DESTDIR)/usr/bin
	chmod 755 $(DESTDIR)/usr/bin/dnssec-monitor
clean:
	rm -f dnssec-monitor
