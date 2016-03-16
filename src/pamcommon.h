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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

static int preprocess(pam_handle_t *pamh,const char **user,const char **pass,
	char *name,int namelen,int try_first_pass,int use_first_pass,int digits)
{
	int r;
	int ulen;
	int plen;
	struct pam_conv *cnv;
	struct pam_message msg;
	struct pam_message *mptr=&msg;
	struct pam_response *rsp=NULL;

	if((r=pam_get_user(pamh,user,NULL))!=PAM_SUCCESS)return r;

	if(try_first_pass||use_first_pass)
	{
		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)pass))!=
			PAM_SUCCESS)return r;

		if(use_first_pass&&!*pass)return PAM_AUTH_ERR;
	}

	if(!*pass)
	{
		if((r=pam_get_item(pamh,PAM_CONV,(const void **)&cnv))!=
			PAM_SUCCESS)return r;

		msg.msg_style=PAM_PROMPT_ECHO_OFF;
		msg.msg="Enter TOTP token: ";

		if((r=cnv->conv(1,(const struct pam_message **)&mptr,&rsp,
			cnv->appdata_ptr))!=PAM_SUCCESS)return r;

		if(!(*pass=rsp->resp))return PAM_AUTH_ERR;
	}

	ulen=strlen(*user);
	if((plen=strlen(*pass))<digits)return PAM_AUTH_ERR;
	else if(plen>digits)
	{
		if(ulen+plen-digits+1>=namelen)return PAM_AUTH_ERR;
		memcpy(name,*user,ulen);
		name[ulen]=':';
		memcpy(name+ulen+1,*pass,plen-digits);
		name[ulen+plen-digits+1]=0;
		*pass+=plen-digits;
		plen=digits;
	}
	else
	{
		if(ulen>=sizeof(name))return PAM_AUTH_ERR;
		strcpy(name,*user);
	}

	while(plen--)if((*pass)[plen]<'0'||(*pass)[plen]>'9')
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
        return PAM_PERM_DENIED;
}
