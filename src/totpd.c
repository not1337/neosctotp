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

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <security/pam_appl.h>
#include <libneosc.h>

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

static int usage(void) __attribute__((noreturn));

static pthread_mutex_t mtx=PTHREAD_MUTEX_INITIALIZER;
static char *path="/var/run/totpd.sock";
static char *pidfile="/var/run/totpd.pid";

#include "config.h"
#include "neoauth.h"

static void handler(int unused)
{
	unlink(path);
	if(pidfile)unlink(pidfile);
	config_clean();
	exit(1);
}

static int mkunix(char *path)
{
	int s;
	mode_t mask;
	struct sockaddr_un a;
	struct stat stb;

	if(!path||strlen(path)>=sizeof(a.sun_path))
	{
		fprintf(stderr,"illegal socket path.\n");
		return -1;
	}

	if((s=socket(PF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0))==-1)
	{
		perror("socket");
		return -1;
	}

	memset(&a,0,sizeof(a));
	a.sun_family=AF_UNIX;
	strcpy(a.sun_path,path);

	if(!lstat(path,&stb))
	{
		if(!S_ISSOCK(stb.st_mode))
		{
			fprintf(stderr,"%s is not a socket\n",path);
			close(s);
			return -1;
		}
		if(unlink(path))
		{
			perror("unlink");
			close(s);
			return -1;
		}
	}

	mask=umask(077);

	if(bind(s,(struct sockaddr *)(&a),sizeof(a)))
	{
		perror("bind");
		umask(mask);
		close(s);
		return -1;
	}

	umask(mask);

	if(listen(s,255))
	{
		perror("listen");
		unlink(path);
		close(s);
		return -1;
	}

	return s;
}

static int mknet(int port)
{
	int s;
	int x;
	struct sockaddr_in6 a;

	memset(&a,0,sizeof(a));
	a.sin6_family=AF_INET6;
	a.sin6_port=htons(port);

	if((s=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0))==-1)
		return -1;

	x=1;
	if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&x,sizeof(x)))
	{
		close(s);
		return -1;
	}

	x=0;
	if(setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&x,sizeof(x)))
	{
		close(s);
		return -1;
	}

	if(bind(s,(struct sockaddr *)(&a),sizeof(a)))
	{
		close(s);
		return -1;
	}

	if(listen(s,255))
	{
		close(s);
		return -1;
	}

	return s;
}

static int reader(int s,unsigned char *bfr)
{
	int i;
	int l;
	struct pollfd p;

	p.fd=s;
	p.events=POLLIN;

repeat:	while(1)
	{
		switch(poll(&p,1,-1))
		{
		case -1:if(errno==EAGAIN)continue;
		case 0:	return -1;
		case 1:	break;
		}
		if(p.revents&(POLLERR|POLLHUP))return -1;
		if(!(p.revents&POLLIN))continue;
		break;
	}

	for(i=0;i<36;)
	{
		switch(poll(&p,1,1000))
		{
		case -1:if(errno==EAGAIN)continue;
		case 0:	goto repeat;
		default:break;
		}
		if(p.revents&(POLLERR|POLLHUP))return -1;
		if(!(p.revents&POLLIN))continue;
		if((l=read(s,bfr+i,36-i))<=0)return -1;
		i+=l;
	}

	while(i<36+bfr[35])
	{
		switch(poll(&p,1,1000))
		{
		case -1:if(errno==EAGAIN)continue;
		case 0:	goto repeat;
		default:break;
		}
		if(p.revents&(POLLERR|POLLHUP))return -1;
		if(!(p.revents&POLLIN))continue;
		if((l=read(s,bfr+i,36+bfr[35]-i))<=0)return -1;
		i+=l;
	}

	return i-36;
}

static void *worker(void *data)
{
        int s=(int)((long)data);
	int i;
	int token;
	int digits;
	int window;
	time_t t=0;
	unsigned char *nk=(unsigned char *)(netkey?netkey:"");
	NEOSC_SHA1(hmac);
	NEOSC_SHA1HMDATA key;
	char name[256];
	unsigned char bfr[291];

	neosc_sha1hmkey(nk,strlen((char *)nk),&key);

	while(1)
	{
		if((i=reader(s,bfr))==-1)break;

		neosc_sha1hmac(bfr+20,i+16,hmac,&key);
		if(memcmp(hmac,bfr,20))continue;
		neosc_sha1hmac(bfr+24,i+12,hmac,&key);
		bfr[20]^=hmac[hmac[19]&0xf];
		bfr[21]^=hmac[(hmac[19]&0xf)+1];
		bfr[22]^=hmac[(hmac[19]&0xf)+2];
		bfr[23]^=hmac[(hmac[19]&0xf)+3];
		neosc_sha1hmac(bfr+20,i+16,hmac,&key);

		memcpy(name,bfr+36,i);
		name[i]=0;
		token=bfr[20];
		token<<=8;
		token|=bfr[21];
		token<<=8;
		token|=bfr[22];
		token<<=8;
		token|=bfr[23];
		for(i=0;i<8;i++)t=(t<<8)|bfr[24+i];
		digits=bfr[32];
		window=bfr[33];

		if(digits<6||digits>8||window<0||window>5||token<0||
			token>100000000)i=PAM_SERVICE_ERR;
		else
		{
			pthread_mutex_lock(&mtx);
			i=neoauth(t,name,token,slot1,slot2,window,digits,serial,
				neokey,tryusb,reset);
			pthread_mutex_unlock(&mtx);
		}

		bfr[20]=(unsigned char)(i>>24)^hmac[hmac[19]&0xf];
		bfr[21]=(unsigned char)(i>>16)^hmac[(hmac[19]&0xf)+1];
		bfr[22]=(unsigned char)(i>>8)^hmac[(hmac[19]&0xf)+2];
		bfr[23]=(unsigned char)i^hmac[(hmac[19]&0xf)+3];
		neosc_sha1hmac(bfr+20,4,bfr,&key);
		i=write(s,bfr,24);

		memclear(hmac,0,sizeof(hmac));
	}

	memclear(hmac,0,sizeof(hmac));
	memclear(&key,0,sizeof(key));
	close(s);
	pthread_exit(NULL);
}

static int usage(void)  
{       
	fprintf(stderr,"Usage: totpd [<options>]\n" );
	fprintf(stderr,"Options:\n");
	fprintf(stderr,"-c <config>  (default: /etc/neototp.conf)\n");
	fprintf(stderr,"-p <pidfile> (default: /var/run/totpd.pid)\n");
	fprintf(stderr,"-s <socket>  (default: /var/run/totpd.sock)\n");
	fprintf(stderr,"-P <port>    (default: none)\n");
	fprintf(stderr,"-f           stay in foreground\n");
	fprintf(stderr,"-h           this help text\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int f=0;
	int p=0;
	int n=-1;
	FILE *fp;
	char *config=(char *)config_default;
	struct pollfd pp[2];
	pthread_t hh;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

	while((c=getopt(argc,argv,"c:p:s:fhP:"))!=-1)switch(c)
	{
	case 'c':
		config=optarg;
		break;
	case 'p':
		pidfile=optarg;
		break;
	case 's':
		path=optarg;
		break;
	case 'f':
		f=1;
		break;
	case 'P':
		p=atoi(optarg);
		break;
	case 'h':
	default:usage();
	}
	if(p<0||p>65535)usage();

	if(config_parse(config,1))return 1;

	if(p)if((n=mknet(p))==-1)return 1;
	if((c=mkunix(path))==-1)return 1;

	signal(SIGINT,handler);
	signal(SIGHUP,handler);
	signal(SIGQUIT,handler);
	signal(SIGTERM,handler);
	signal(SIGPIPE,SIG_IGN);

	if(!f)
	{
		if(daemon(0,0))
		{
			perror("daemon");
			return 1;
		}
		if((fp=fopen(pidfile,"we")))
		{
			fprintf(fp,"%d\n",getpid());
			fclose(fp);
		}
	}
	else pidfile=NULL;

	pp[0].fd=c;
	pp[0].events=POLLIN;
	pp[1].fd=n;
	pp[1].events=POLLIN;
	pp[1].revents=0;
	n=(n==-1?1:2);

	while(1)
	{
		if(poll(pp,n,-1)<1)continue;
		if(pp[0].revents&POLLIN)
			if((f=accept4(pp[0].fd,NULL,NULL,SOCK_CLOEXEC))!=-1)
		{
			if(pthread_create(&hh,&attr,worker,(void *)((long)f)))
				close(f);
		}

		if(pp[1].revents&POLLIN)
			if((f=accept4(pp[1].fd,NULL,NULL,SOCK_CLOEXEC))!=-1)
		{
			c=1;
			if(setsockopt(f,IPPROTO_TCP,TCP_NODELAY,&c,sizeof(c)))
			{
				close(f);
				continue;
			}
			if(pthread_create(&hh,&attr,worker,(void *)((long)f)))
				close(f);
		}
	}

	return 0;
}
