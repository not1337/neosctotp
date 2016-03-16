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

typedef struct
{
	int head;
	int tail;
	struct
	{
		char host[64];
		time_t stamp;
	} entry[32];
} CACHEENTRY;

static void fatal(const char *unused)
{
}

static int validaddr(const char *cfgfile,const char *rhost)
{
	int mode=0;
	int inmode=0;
	int len=0;
	int i;
	int l;
	char *ptr;
	char *mem;
	FILE *fp;
	unsigned char addr[16];
	unsigned char in[16];
	char line[256];

	if(!cfgfile)return 1;

	if(!(fp=fopen(cfgfile,"re")))return 0;

	if(inet_pton(AF_INET,rhost,addr)==1)mode=1;
	else if(inet_pton(AF_INET6,rhost,addr)==1)mode=2;
	else len=strlen(rhost);

	while(fgets(line,sizeof(line),fp))
	{
		if(!(ptr=strtok_r(line," \t\r\n",&mem))||!*ptr||*ptr=='#')
			continue;
		if((mem=strrchr(ptr,'/')))*mem=0;
		if(inet_pton(AF_INET,ptr,in)==1)inmode=1;
		else if(inet_pton(AF_INET6,ptr,in)==1)inmode=2;
		else inmode=0;
		if(inmode!=mode)continue;
		if(mem)
		{
			*mem++='/';
			if(inmode)
			{
				if(!*mem)continue;
				if((len=atoi(mem))<0)continue;
				if(inmode==1&&len>32)continue;
				else if(inmode==2&&len>128)continue;
			}
		}
		else if(inmode==1)len=32;
		else if(inmode==2)len=128;

		if(!mode)
		{
			if((l=strlen(ptr))>len)continue;
			if(strcasecmp(ptr,rhost+len-l))continue;
		}
		else
		{
			for(i=0,l=len>>3;i<l;i++)if(addr[i]!=in[i])break;
			if(i!=l)continue;
			if((l=len&7))
			{
				l=(0xff<<(8-l))&0xff;
				if((addr[i]&l)!=(in[i]&l))continue;
			}
		}

		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
}


static int cachecheck(pam_handle_t *pamh,const char *cachedb,const char *cmp,
	int valid,int mode)
{
	int i;
	int dirty=0;
	int r=PAM_AUTHINFO_UNAVAIL;
	time_t now;
	const char *user=NULL;
	const char *rhost=NULL;
	GDBM_FILE db;
	datum key;
	datum data;
	char host[64];
	CACHEENTRY *old,new;

	now=time(NULL);

	if((i=pam_get_user(pamh,&user,NULL))!=PAM_SUCCESS)return i;
	if((i=pam_get_item(pamh,PAM_RHOST,(const void **)&rhost))!=PAM_SUCCESS)
		return i;
	if(!user||!*user||!rhost||!*rhost)return r;

	if(!(db=gdbm_open(cachedb,4096,GDBM_WRCREAT,0600,fatal)))return r;

	strncpy(host,rhost,64);
	host[63]=0;

	key.dptr=(char *)user;
	key.dsize=strlen(user)+1;

	data=gdbm_fetch(db,key);
	old=(void *)data.dptr;

	if(old&&data.dsize!=sizeof(new))
	{
		free(old);
		old=NULL;
	}

	if(!old)memset(&new,0,sizeof(new));
	else
	{
		new=*old;
		free(old);
		while(new.tail!=new.head)
		{
			if(new.entry[new.tail].stamp>=now-valid)break;
			if(++new.tail==32)new.tail=0;
			dirty=1;
		}
		for(i=new.tail;i!=new.head;)
		{
			if(!strcmp(new.entry[i].host,host))
			{
				if(mode)
				{
					new.entry[i].stamp=now;
					dirty=1;
				}
				r=PAM_SUCCESS;
				break;
			}
			if(++i==32)i=0;
		}
	}

	if(dirty)
	{
		data.dptr=(void *)&new;
		data.dsize=sizeof(new);
		gdbm_store(db,key,data,GDBM_REPLACE);
	}

	gdbm_close(db);
	return r;
}

static void cacheadd(pam_handle_t *pamh,const char *cachedb,const char *cmp)
{
	int i;
	time_t now;
	const char *user=NULL;
	const char *rhost=NULL;
	GDBM_FILE db;
	datum key;
	datum data;
	char host[64];
	CACHEENTRY *old,new;

	now=time(NULL);

	if((i=pam_get_user(pamh,&user,NULL))!=PAM_SUCCESS)return;
	if((i=pam_get_item(pamh,PAM_RHOST,(const void **)&rhost))!=PAM_SUCCESS)
		return;
	if(!user||!*user||!rhost||!*rhost)return;

	if(!validaddr(cmp,rhost))return;

	if(!(db=gdbm_open(cachedb,4096,GDBM_WRCREAT,0600,fatal)))return;

	strncpy(host,rhost,64);
	host[63]=0;

	key.dptr=(char *)user;
	key.dsize=strlen(user)+1;

	data=gdbm_fetch(db,key);
	old=(void *)data.dptr;

	if(old&&data.dsize!=sizeof(new))
	{
		free(old);
		old=NULL;
	}

	if(!old)memset(&new,0,sizeof(new));
	else
	{
		new=*old;
		free(old);
	}

	for(i=new.tail;i!=new.head;)
	{
		if(!strcmp(new.entry[i].host,host))
		{
			new.entry[i].stamp=now;
			break;
		}
		if(++i==32)i=0;
	}

	if(i==new.head)
	{
		strcpy(new.entry[i].host,host);
		new.entry[i].stamp=now;
		if(++new.head==32)new.head=0;
		if(new.head==new.tail)if(++new.tail==32)new.tail=0;
	}

	data.dptr=(void *)&new;
	data.dsize=sizeof(new);
	gdbm_store(db,key,data,GDBM_REPLACE);
}

static int replaycheck(pam_handle_t *pamh,const char *replaydb,
	const char *cmp,char *name,int token,time_t t)
{
	int i;
	int replayok=0;
	const char *rhost=NULL;
	GDBM_FILE db;
	datum key;
	datum data;

	struct
	{
		int head;
		int tail;
		int value[12];
		time_t stamp[12];
	} *old,new;

	if(cmp)
	{
		if(pam_get_item(pamh,PAM_RHOST,(const void **)&rhost)!=
			PAM_SUCCESS)rhost=NULL;
		else if(rhost&&!*rhost)rhost=NULL;

		if(rhost&&validaddr(cmp,rhost))replayok=1;
	}

	if(!(db=gdbm_open(replaydb,4096,GDBM_WRCREAT,0600,fatal)))
		return PAM_AUTHINFO_UNAVAIL;

	key.dptr=name;
	key.dsize=strlen(name)+1;

	data=gdbm_fetch(db,key);
	old=(void *)data.dptr;

	if(old&&data.dsize!=sizeof(new))
	{
		free(old);
		old=NULL;
	}

	if(!old)
	{
		memset(&new,0,sizeof(new));
		new.value[new.head]=token;
		new.stamp[new.head++]=t;
	}
	else
	{
		new=*old;
		free(old);
		while(new.tail!=new.head)
		{
			if(new.stamp[new.tail]>t-10*NEOSC_OATH_STEP)break;
			if(++new.tail==12)new.tail=0;
		}
		for(i=new.tail;i!=new.head;)
		{
			if(new.value[i]==token)
			{
				gdbm_close(db);
				return replayok?PAM_SUCCESS:PAM_AUTH_ERR;
			}
			if(++i==12)i=0;
		}
		new.value[new.head]=token;
		new.stamp[new.head]=t;
		if(++new.head==12)new.head=0;
		if(new.head==new.tail)if(++new.tail==12)new.tail=0;
	}

	data.dptr=(void *)&new;
	data.dsize=sizeof(new);
	if(gdbm_store(db,key,data,GDBM_REPLACE))
	{
		gdbm_close(db);
		return replayok?PAM_SUCCESS:PAM_AUTHINFO_UNAVAIL;
	}

	gdbm_close(db);
	return PAM_SUCCESS;
}
