PREFIX=/usr/local

ttcdt-sodium: ttcdt-sodium.c
	$(CC) -g -Wall $< `pkg-config --cflags --libs libsodium` -o $@

install:
	install -m 755 ttcdt-sodium $(PREFIX)/bin/ttcdt-sodium

uninstall:
	rm -f $(PREFIX)/bin/ttcdt-sodium

dist: clean
	cd .. && tar czvf ttcdt-sodium/ttcdt-sodium.tar.gz ttcdt-sodium/*

clean:
	rm -f ttcdt-sodium *.tar.gz *.asc
