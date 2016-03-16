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

static const char *config_default="/etc/neototp.conf";
static const char *slot1=NULL;
static const char *slot2=NULL;
static const char *neokey=NULL;
static const char *netkey=NULL;
static int serial=0;
static int tryusb=0;
static int reset=0;

static void clean1(char *data)
{
	if(data)
	{
		memclear(data,0,strlen(data));
		free(data);
		data=NULL;
	}
}

static void config_clean(void)
{
	clean1((char *)slot1);
	clean1((char *)slot2);
	clean1((char *)neokey);
	clean1((char *)netkey);
	serial=0;
	tryusb=0;
	reset=0;
}

static int config_parse(char *config,int verbose)
{
	char *name;
	char *value;
	FILE *fp;
	char bfr[2048];

	if(!(fp=fopen(config,"re")))
	{
		if(verbose)perror("fopen");
		return -1;
	}

	while(fgets(bfr,sizeof(bfr),fp))
		if((name=strtok(bfr," \t=\r\n")))if(*name&&*name!='#')
	{
		if(!(value=strtok(NULL,"\r\n"))||!*value)goto err;
		if(!strcmp(name,"slot1"))slot1=strdup(value);
		else if(!strcmp(name,"slot2"))slot2=strdup(value);
		else if(!strcmp(name,"neokey"))neokey=strdup(value);
		else if(!strcmp(name,"netkey"))netkey=strdup(value);
		else if(!strcmp(name,"serial"))serial=atoi(value);
		else if(!strcmp(name,"tryusb"))tryusb=atoi(value);
		else if(!strcmp(name,"reset"))
		{
			if(!strcmp(value,"none"))reset=0;
			else if(!strcmp(value,"neo"))reset=1;
			else if(!strcmp(value,"ndef"))reset=2;
			else if(!strcmp(value,"pgp"))reset=3;
			else if(!strcmp(value,"piv"))reset=4;
			else goto err;
		}
		else
		{
err:			if(verbose)fprintf(stderr,"config file syntax error\n");
			fclose(fp);
			config_clean();
			return -1;
		}
	}

	fclose(fp);
	return 0;
}
