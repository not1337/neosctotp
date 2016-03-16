/*
 * This file is part of the neosctotp project, which allows a YubiKey NEO(-N)
 * to be used on a client or on a server for TOTP two factor authentication.
 *
 * Copyright (c) 2015 Andreas Steinmetz, ast@domdv.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <security/pam_appl.h>
#include <libneosc.h>

static int usage(void) __attribute__((noreturn));

#include "sha1.h"
#include "config.h"
#define COMM_UNIX
#define COMM_NET
#define COMM_SERIAL
#include "client.h"

static int usage(void)
{
    fprintf(stderr,"Usage:\n"
    "totpclient -D <device> -L <lockfile> -n <name> -t <token>|- <options>\n"
    "totpclient -H <host> -P <port> -n <name> -t <token>|- <options>\n"
    "totpclient [-s <socket>] -n <name> -t <token>|- <options>\n"
    "totpclient -h\n"
    "\n"
    "Serial Line Options:\n"
    "-D  serial device (no default)\n"
    "-L  lock file (no default)\n"
    "\n"
    "TCP Options:\n"
    "-H  remote host name (no default)\n"
    "-P  remote host port (no default)\n"
    "-i  IPv6 link local interface (no default)\n"
    "\n"
    "Unix Domain Socket Options:\n"
    "-s  socket name (default: /var/run/totpd.sock)\n"
    "\n"
    "Common Options:\n"
    "-n  authentication name (no default)\n"
    "-t  authentication token or '-' to read from standard input (no default)\n"
    "-d  digits (6-8, default: 6)\n"
    "-w  window (0-5, default: 0)\n"
    "-c  configuration file (default: /etc/neototp.conf)\n"
    "-h  this help text\n");
    exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int digits=6;
	int window=0;
	int token=-1;
	int port=0;
	time_t t=time(NULL);
	char *sock="/var/run/totpd.sock";
	char *name=NULL;
	char *host=NULL;
	char *device=NULL;
	char *lock=NULL;
	char *ifc=NULL;
	char *config=(char *)config_default;
	char bfr[128];

	while((c=getopt(argc,argv,"n:d:w:t:s:c:H:P:D:L:i:h"))!=-1)switch(c)
	{
	case 'n':
		name=optarg;
		break;
	case 'd':
		digits=atoi(optarg);
		break;
	case 'w':
		window=atoi(optarg);
		break;
	case 't':
		if(!strcmp(optarg,"-"))
		{
			if(!fgets(bfr,sizeof(bfr),stdin))usage();
			token=atoi(bfr);
		}
		else token=atoi(optarg);
		break;
	case 's':
		sock=optarg;
		break;
	case 'c':
		config=optarg;
		break;
	case 'H':
		host=optarg;
		break;
	case 'P':
		port=atoi(optarg);
		break;
	case 'D':
		device=optarg;
		break;
	case 'L':
		lock=optarg;
		break;
	case 'i':
		ifc=optarg;
		break;
	case 'h':
	default:usage();
	}

	if(!name||digits<6||digits>8||window<0||window>5||token<0)usage();
	if(host)
	{
		if(!*host||port<1||port>65535)usage();
	}
	else if(port)usage();

	if((device&&!lock)||(!device&&lock))usage();
	if(device&&(!*device||!*lock))usage();

	if(device&&host)usage();

	if(config_parse(config,1))return 1;

	if(device)
	{
		if(rmtclient(device,lock,t,name,token,digits,window,&c,netkey)||
			c!=PAM_SUCCESS)
		{
			config_clean();
			return 1;
		}
	}
	else if(host)
	{
		if(netclient(host,port,ifc,t,name,token,digits,window,&c,
			netkey)||c!=PAM_SUCCESS)
		{
			config_clean();
			return 1;
		}
	}
	else if(unxclient(sock,t,name,token,digits,window,&c,netkey)||
		c!=PAM_SUCCESS)
	{
		config_clean();
		return 1;
	}

	config_clean();
	return 0;
}
