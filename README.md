#neosctotp
TOTP authentication using the YubiKey NEO(-N)

The stuff contained in this directory allows a YubiKey NEO(-N) to be used on
a client or on a server for TOTP two factor authentication. Please keep in
mind that a YubiKey is not the fastest device and that the OATH applet has
a memory limitation of 2048 bytes (each entry consists of the UTF8 entry
name and 9 additional bytes) for TOTP tokens. So try not to use a YubiKey on
a multi user and/or busy server. It is ok, however, to use a YubiKey even
on a busy server if TOTP is restricted to e.g. only the few administrative
users.


TOTP daemon
===========

Used to provide serialized access to the YubiKey OATH applet.

Usage: totpd [<options>]
-c <config>  (default: /etc/neototp.conf)
-p <pidfile> (default: /var/run/totpd.pid)
-s <socket>  (default: /var/run/totpd.sock)
-P <port>    (default: none)
-f           stay in foreground
-h           this help text


TOTP daemon client:
===================

Allows for non PAM token verification access to the TOTP daemon.

Usage:
totpclient -D <device> -L <lockfile> -n <name> -t <token>|- <options>
totpclient -H <host> -P <port> -n <name> -t <token>|- <options>
totpclient [-s <socket>] -n <name> -t <token>|- <options>
totpclient -h

Serial Line Options:
-D  serial device (no default)
-L  lock file (no default)

TCP Options:
-H  remote host name (no default)
-P  remote host port (no default)
-i  IPv6 link local interface (no default)

Unix Domain Socket Options:
-s  socket name (default: /var/run/totpd.sock)

Common Options:
-n  authentication name (no default)
-t  authentication token or '-' to read from standard input (no default)
-d  digits (6-8, default: 6)
-w  window (0-5, default: 0)
-c  configuration file (default: /etc/neototp.conf)
-h  this help text


TOTP user tool:
===============

Used by users to get a TOTP token from a YubiKey.

Usage: totptool <options>
-I             short for -C ISO8859-15
-U             short for -C UTF8
-C <charset>   command line charset (default: ASCII)
-1             use slot 1 instead of OATH applet
-2             use slot 2 instead of OATH applet
-6             calculate 6 digits (slot 1 and slot 2)
-7             calculate 7 digits (slot 1 and slot 2)
-8             calculate 8 digits (slot 1 and slot 2)
-s <serial>    use YubiKey with given serial number
-u             use first USB attached YubiKey without serial number
-n             use first NFC attached YubiKey
-p             prefix the output with the name given with -N or -X
-X             output prefix, if specified has priority over -N
-x             output result in format usable by xdotool
-P <passfile>  file containing single line with OATH applet password
-N <name>      OATH applet TOTP token name
-v             print error message in case of failures
-r             append CR to output
-l             append LF to output
-a             switch to PIV applet after processing
-A             switch to OpenPGP applet after processing
-h             this help text


PAM modules:
============

pam_neototp.so	for standalone systems and hosts of virtual systems
pam_rmttotp.so	for guests, access host YubiKey via virtual serial device
pam_nettotp.so	for guests, access host YubiKey via network (host only!)

Please note that pam_rmttotp.so and pam_nettotp.so are designed only for
guests (preferably qemu and pam_rmttotp.so). If you need to use pam_nettotp.so
you should use a host only network between guest and host, furthermore
the TOTP daemon port on the host must be properly protected by ip(6)tables
rules.

Common options:
---------------

use_first_pass		try to use already provided token,
			otherwise request token from user

alwaysok		always return token success - testing only!

digits=6|7|8		required token digits (optionally provided prefix
			is appended to username like username:prefix for
			replay check and YubiKey totp selection)

window=0|1|2|3|4|5	token validity check width (current time +- window*30s)

config=<pathname>	YubiKey and  TOTP daemon access and configuration

replaydb=<pathname>	gdbm database used for token replay checking

replayok=<pathname>	hosts/networks/domains for which replay checking
			is ignored

cachedb=<pathname>	gdbm database containing cached successful
			authentication (used to skip token checking)

cachehosts=<pathname>	hosts/networks/domains for which authentication
			cacheing is allowed

valid=1-86400		authentication cache valid time in seconds
			(default 1800)

retrigger		any new access using cached authentication
			credentials restarts the authentication valid time

pam_neototp.so options:
-----------------------

socket=<pathname>	TOTP daemon communication socket

pam_rmttotp.so options:
-----------------------

device=<device>		qemu virtual serial device
lock=<pathname>		serial device lock file pathname (think modem!)

pam_nettotp.so options:
-----------------------

host=<hostname-or-ip>	host address of the TOTP daemon host
port=<1-65535>		port number the TOTP daemon is listening on


Compiling for virtual guests:
=============================

The "src" directory includes a simple "Makefile.guest" which builds the stuff
suitable for virtual guests. No install included, this must then be done
manually.
