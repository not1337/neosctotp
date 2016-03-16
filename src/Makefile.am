man_MANS = pam_neototp.8 pam_nettotp.8 pam_rmttotp.8 totpd.1 totpclient.1 totptool.1

noinst_HEADERS = client.h config.h dbstuff.h neoauth.h pamcommon.h sha1.h

sbin_PROGRAMS = totpd totpclient

bin_PROGRAMS = totptool

securelib_LTLIBRARIES = pam_neototp.la pam_nettotp.la pam_rmttotp.la
securelibdir = $(libdir)/security

pam_neototp_la_SOURCES = pam_neototp.c client.h config.h dbstuff.h neoauth.h pamcommon.h
pam_neototp_la_CFLAGS = -Wall -O3 -fPIC
pam_neototp_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_neototp_la_LIBADD = -lgdbm -lneosc -lpam

pam_nettotp_la_SOURCES = pam_nettotp.c client.h config.h dbstuff.h pamcommon.h sha1.h
pam_nettotp_la_CFLAGS = -Wall -O3 -fPIC
pam_nettotp_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_nettotp_la_LIBADD = -lgdbm -lpam

pam_rmttotp_la_SOURCES = pam_rmttotp.c client.h config.h dbstuff.h pamcommon.h sha1.h
pam_rmttotp_la_CFLAGS = -Wall -O3 -fPIC
pam_rmttotp_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_rmttotp_la_LIBADD = -lgdbm -lpam

totpd_SOURCES = totpd.c config.h neoauth.h
totpd_CFLAGS = -Wall -O3
totpd_LDADD = -lpthread -lneosc

totpclient_SOURCES = totpclient.c config.h client.h sha1.h
totpclient_CFLAGS = -Wall -O3

totptool_SOURCES = totptool.c
totptool_CFLAGS = -Wall -O3
totptool_LDADD  = -lneosc

install-exec-hook:
	strip $(sbindir)/totpd
	strip $(sbindir)/totpclient
	strip $(bindir)/totptool

install-data-hook:
	rm -f $(securelibdir)/pam_neototp.la
	rm -f $(securelibdir)/pam_nettotp.la
	rm -f $(securelibdir)/pam_rmttotp.la
	install -o root -g root -m 600 authcache.conf.example /etc/authcache.conf.example
	install -o root -g root -m 600 neototp.conf.example /etc/neototp.conf.example
	install -o root -g root -m 600 replayhosts.conf.example /etc/replayhosts.conf.example
