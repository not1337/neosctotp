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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <gdbm.h>
#include <libneosc.h>

#include "sha1.h"
#include "config.h"
#define COMM_NET
#include "client.h"
#include "pamcommon.h"
#include "dbstuff.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	int i;
	int r;
	int try_first_pass=0;
	int use_first_pass=0;
	int alwaysok=0;
	int mode=0;
	int digits=6;
	int window=0;
	int valid=1800;
	int port=0;
	time_t t;
	const char *user=NULL;
	const char *pass=NULL;
	const char *config=config_default;
	const char *host=NULL;
	const char *replaydb=NULL;
	const char *cachedb=NULL;
	const char *cmp=NULL;
	const char *rcmp=NULL;
	const char *ifc=NULL;
	char name[256];

	for(i=0;i<argc;i++)if(!strcmp(argv[i],"try_first_pass"))
		try_first_pass=1;
	else if(!strcmp(argv[i],"use_first_pass"))use_first_pass=1;
	else if(!strcmp(argv[i],"alwaysok"))alwaysok=1;
	else if(!strcmp(argv[i],"retrigger"))mode=1;
	else if(!strncmp(argv[i],"digits=",7))digits=atoi(&argv[i][7]);
	else if(!strncmp(argv[i],"window=",7))window=atoi(&argv[i][7]);
	else if(!strncmp(argv[i],"valid=",6))valid=atoi(&argv[i][6]);
	else if(!strncmp(argv[i],"config=",7))config=&argv[i][7];
	else if(!strncmp(argv[i],"host=",5))host=&argv[i][5];
	else if(!strncmp(argv[i],"port=",5))port=atoi(&argv[i][5]);
	else if(!strncmp(argv[i],"interface=",10))ifc=&argv[i][10];
	else if(!strncmp(argv[i],"replaydb=",9))replaydb=&argv[i][9];
	else if(!strncmp(argv[i],"cachedb=",8))cachedb=&argv[i][8];
	else if(!strncmp(argv[i],"cachehosts=",11))cmp=&argv[i][11];
	else if(!strncmp(argv[i],"replayok=",9))rcmp=&argv[i][9];

	if(config_parse((char *)config,0)||!host||!*host||port<1||port>65535||
		digits<6||digits>8||window<0||window>5||valid<=0||valid>86400)
	{
		r=PAM_SERVICE_ERR;
		goto out;
	}

	if(cachedb&&(r=cachecheck(pamh,cachedb,cmp,valid,mode))==PAM_SUCCESS)
		goto out;

	if((r=preprocess(pamh,&user,&pass,name,sizeof(name),try_first_pass,
		use_first_pass,digits))!=PAM_SUCCESS)goto out;

        t=time(NULL);
        if(netclient(host,port,ifc,t,name,atoi(pass),digits,window,&r,netkey))
	{
		r=PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	else if(r==PAM_SUCCESS&&replaydb)
		r=replaycheck(pamh,replaydb,rcmp,name,atoi(pass),t);
	if(r==PAM_SUCCESS&&cachedb)cacheadd(pamh,cachedb,cmp);

out:	config_clean();
	if(alwaysok)return PAM_SUCCESS;
	return r;
}

#ifdef PAM_STATIC

struct pam_module _pam_nettotp_modstruct=
{
	"pam_nettotp",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
