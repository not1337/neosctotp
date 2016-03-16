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

#ifndef memclear
#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)
#endif

static int doauth(int s,time_t t,char *name,int token,int digits,int window,
	unsigned char *netkey,int *result)
{
	int len;
	int i;
	int r=-1;
	NEOSC_SHA1(hmac1);
	NEOSC_SHA1(hmac2);
	NEOSC_SHA1HMDATA key;
	unsigned char bfr[291];

	if(!netkey)netkey=(unsigned char *)"";

	if((len=strlen(name))>255)len=255;

	bfr[20]=(unsigned char)(token>>24);
	bfr[21]=(unsigned char)(token>>16);
	bfr[22]=(unsigned char)(token>>8);
	bfr[23]=(unsigned char)token;
	if(sizeof(t)>4)
	{
		bfr[24]=(unsigned char)(t>>56);
		bfr[25]=(unsigned char)(t>>48);
		bfr[26]=(unsigned char)(t>>40);
		bfr[27]=(unsigned char)(t>>32);
	}
	else
	{
		bfr[24]=0x00;
		bfr[25]=0x00;
		bfr[26]=0x00;
		bfr[27]=0x00;
	}
	bfr[28]=(unsigned char)(t>>24);
	bfr[29]=(unsigned char)(t>>16);
	bfr[30]=(unsigned char)(t>>8);
	bfr[31]=(unsigned char)t;
	bfr[32]=(unsigned char)digits;
	bfr[33]=(unsigned char)window;
	bfr[34]=0x00;
	bfr[35]=(unsigned char)len;
	memcpy(bfr+36,name,len);

	neosc_sha1hmkey(netkey,strlen((char *)netkey),&key);
	neosc_sha1hmac(bfr+24,len+12,hmac1,&key);
	neosc_sha1hmac(bfr+20,len+16,hmac2,&key);
	bfr[20]^=hmac1[hmac1[19]&0xf];
	bfr[21]^=hmac1[(hmac1[19]&0xf)+1];
	bfr[22]^=hmac1[(hmac1[19]&0xf)+2];
	bfr[23]^=hmac1[(hmac1[19]&0xf)+3];
	neosc_sha1hmac(bfr+20,len+16,bfr,&key);

	if(write(s,bfr,len+36)!=len+36)goto out;
	for(len=0;len<24;len+=i)if((i=read(s,bfr+len,24-len))<=0)goto out;

	neosc_sha1hmac(bfr+20,4,hmac1,&key);
	if(memcmp(bfr,hmac1,20))goto out;

	*result=bfr[20]^hmac2[hmac2[19]&0xf];
	*result<<=8;
	*result|=bfr[21]^hmac2[(hmac2[19]&0xf)+1];
	*result<<=8;
	*result|=bfr[22]^hmac2[(hmac2[19]&0xf)+2];
	*result<<=8;
	*result|=bfr[23]^hmac2[(hmac2[19]&0xf)+3];

	r=0;

out:	memclear(hmac1,0,sizeof(hmac1));
	memclear(hmac2,0,sizeof(hmac2));
	memclear(&key,0,sizeof(key));

	return r;
}

#ifdef COMM_NET

static int netclient(const char *host,int port,const char *interface,time_t t,
	char *name,int token,int digits,int window,int *result,
	const char *netkey)
{
	int s;
	int i;
	struct hostent *h;
	struct hostent hh;
	union
	{
		struct sockaddr_in6 a6;
		struct sockaddr_in a4;
	} addr;
	struct sockaddr *a=(struct sockaddr *)&addr;
	char bfr[2048];

	memset(&addr,0,sizeof(addr));

	if(inet_pton(AF_INET6,host,&addr.a6.sin6_addr)==1)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
	}
	else if(inet_pton(AF_INET,host,&addr.a4.sin_addr)==1)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
	}
	else if(!gethostbyname2_r(host,AF_INET6,&hh,bfr,sizeof(bfr),&h,&s)&&h)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
		memcpy(&addr.a6.sin6_addr,h->h_addr,16);
	}
	else if(!gethostbyname2_r(host,AF_INET,&hh,bfr,sizeof(bfr),&h,&s)&&h)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
		memcpy(&addr.a4.sin_addr,h->h_addr,4);
	}
	else return -1;

	if((s=socket(a->sa_family,SOCK_STREAM|SOCK_CLOEXEC,0))==-1)return -1;

	if(interface)
	{
		if(a->sa_family==AF_INET)goto fail;
		if(!(addr.a6.sin6_scope_id=if_nametoindex(interface)))goto fail;
		i=1;
		if(setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&i,sizeof(i)))
			goto fail;
	}

	i=1;
	if(setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&i,sizeof(i)))goto fail;

	if(connect(s,a,sizeof(addr)))
	{
fail:		close(s);
		return -1;
	}

	i=doauth(s,t,name,token,digits,window,(unsigned char *)netkey,result);

	close(s);

	return i;
}

#endif

#ifdef COMM_UNIX

static int unxclient(const char *sock,time_t t,char *name,int token,int digits,
	int window,int *result,const char *netkey)
{
	int c;
	int i;
	struct stat stb;
	struct sockaddr_un a;

	if(stat(sock,&stb))return -1;
	if(!S_ISSOCK(stb.st_mode))return -1;
	if(access(sock,R_OK|W_OK))return -1;
	if(strlen(sock)>=sizeof(a.sun_path))return -1;

	if((c=socket(PF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0))==-1)return -1;
	memset(&a,0,sizeof(a));
	a.sun_family=AF_UNIX;
	strcpy(a.sun_path,sock);

	if(connect(c,(struct sockaddr *)(&a),sizeof(a)))
	{
		close(c);
		return -1;
	}

	i=doauth(c,t,name,token,digits,window,(unsigned char *)netkey,result);

	close(c);

	return i;
}

#endif

#ifdef COMM_SERIAL

static int rmtclient(const char *device,const char *lock,time_t t,char *name,
	int token,int digits,int window,int *result,const char *netkey)
{
	int i=-1;
	int l;
	int s;
	struct termios tt;

	if((l=open(lock,O_RDWR|O_CREAT|O_CLOEXEC,0600))==-1)goto err1;
	if(lockf(l,F_LOCK,0))goto err2;
	if((s=open(device,O_RDWR|O_CLOEXEC))==-1)goto err2;
	if(tcgetattr(s,&tt)<0)goto err3;
	tt.c_cflag=CS8|CREAD;
	tt.c_iflag=IGNBRK|IGNPAR;
	tt.c_oflag=0;
	tt.c_lflag=0;
	for(i=0;i<NCCS;i++)tt.c_cc[i]=0;
	tt.c_cc[VMIN]=1;
	tt.c_cc[VTIME]=0;
	cfsetispeed(&tt,B115200);
	cfsetospeed(&tt,B115200);
	if(tcsetattr(s,TCSAFLUSH,&tt)<0)goto err3;
	tcflush(s,TCIOFLUSH);

	i=doauth(s,t,name,token,digits,window,(unsigned char *)netkey,result);

	tcflush(s,TCIOFLUSH);

err3:	close(s);
err2:	close(l);
err1:	return i;
}

#endif
