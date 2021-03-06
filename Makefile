PREFIX = $(HOME)/.local
INSTALL_DIR = $(PREFIX)/bin

all: osws

install: osws
	cp osws $(INSTALL_DIR)

clean:
	rm -f osws

osws: osws.c
	$(CC) -std=c99 -Wall -o osws osws.c -lmagic

release: clean
	(cd /tmp && \
	mkdir osws-$(VERSION) && \
	cp -a $$OLDPWD/* osws-$(VERSION) && \
	tar cjf $(HOME)/osws-$(VERSION).tar.bz2 osws-$(VERSION) && \
	tar cv osws-$(VERSION) | lzma -c > $(HOME)/osws-$(VERSION).tar.lzma && \
	rm -rf osws-$(VERSION) )

.PHONY: all install clean release
