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

static void neoapp(void *ctx,int mode)
{
	switch(mode)
	{
	case 1: neosc_neo_select(ctx,NULL);
		break;
	case 2: neosc_ndef_select(ctx);
		break;
	case 3: neosc_pgp_select(ctx);
		break;
	case 4: neosc_piv_select(ctx);
		break;
	}

}

static int neoauth(time_t t,char *name,int token,const char *slot1,
	const char *slot2,int window,int digits,int serial,const char *neokey,
	int tryusb,int reset)
{
	int i;
	int delta;
	int val;
	void *ctx;
	int type=0;
	NEOSC_OATH_INFO info;
	NEOSC_OATH_RESPONSE res;
	NEOSC_SHA1(hmac);
	unsigned char chal[8];

	if(slot1&&!strcmp(name,slot1))type=1;
	else if(slot2&&!strcmp(name,slot2))type=2;

	if(neosc_pcsc_open(&ctx,serial))goto err0;

	if(neosc_pcsc_lock(ctx))
	{
		neosc_pcsc_close(ctx);
err0:		if(type)goto usb;
		return PAM_AUTHINFO_UNAVAIL;
	}

	if(type)
	{
		if(neosc_neo_select(ctx,NULL))goto err1;

		for(i=0;i<=window;i++)
		{
			delta=i*NEOSC_OATH_STEP;
			neosc_util_time_to_array(t-delta,chal,sizeof(chal));
			if(neosc_neo_read_hmac(ctx,type-1,chal,sizeof(chal),
				hmac,sizeof(hmac)))goto err2;
			neosc_util_sha1_to_otp(hmac,sizeof(hmac),digits,&val);
			if(val==token)goto ok;
			if(!i)continue;
			neosc_util_time_to_array(t+delta,chal,sizeof(chal));
			if(neosc_neo_read_hmac(ctx,type-1,chal,sizeof(chal),
				hmac,sizeof(hmac)))
			{
err2:				neoapp(ctx,reset);
err1:				neosc_pcsc_unlock(ctx);
				neosc_pcsc_close(ctx);
				goto usb;
			}
			neosc_util_sha1_to_otp(hmac,sizeof(hmac),digits,&val);
			if(val==token)goto ok;
		}
	}
	else
	{
		if(neosc_oath_select(ctx,&info))goto err3;

		if(info.protected)
			if(!neokey||neosc_oath_unlock(ctx,(char *)neokey,&info))
		{
err3:				neoapp(ctx,reset);
				neosc_pcsc_unlock(ctx);
				neosc_pcsc_close(ctx);
				return PAM_AUTHINFO_UNAVAIL;
		}

		for(i=0;i<=window;i++)
		{
			delta=i*NEOSC_OATH_STEP;
			if(neosc_oath_calc_single(ctx,name,t-delta,&res))
				break;
			if(res.digits==digits&&res.value==token)goto ok;
			if(!i)continue;
			if(neosc_oath_calc_single(ctx,name,t+delta,&res))
				break;
			if(res.digits==digits&&res.value==token)
			{
ok:				neoapp(ctx,reset);
				neosc_pcsc_unlock(ctx);
				neosc_pcsc_close(ctx);
				return PAM_SUCCESS;
			}
		}

		neoapp(ctx,reset);
	}

	neosc_pcsc_unlock(ctx);
	neosc_pcsc_close(ctx);
	return PAM_AUTH_ERR;

usb:	if(!tryusb)return PAM_AUTHINFO_UNAVAIL;

	if(neosc_usb_open(&ctx,serial,NULL))return PAM_AUTHINFO_UNAVAIL;

	for(i=0;i<=window;i++)
	{
		delta=i*NEOSC_OATH_STEP;
		neosc_util_time_to_array(t-delta,chal,sizeof(chal));
		if(neosc_usb_read_hmac(ctx,type-1,chal,sizeof(chal),
			hmac,sizeof(hmac)))goto err4;
		neosc_util_sha1_to_otp(hmac,sizeof(hmac),digits,&val);
		if(val==token)goto ok2;
		if(!i)continue;
		neosc_util_time_to_array(t+delta,chal,sizeof(chal));
		if(neosc_usb_read_hmac(ctx,type-1,chal,sizeof(chal),
			hmac,sizeof(hmac)))
		{
err4:			neosc_usb_close(ctx);
			return PAM_AUTHINFO_UNAVAIL;
		}
		neosc_util_sha1_to_otp(hmac,sizeof(hmac),digits,&val);
		if(val==token)
		{
ok2:			neosc_usb_close(ctx);
			return PAM_SUCCESS;
		}
	}

	neosc_usb_close(ctx);
	return PAM_AUTH_ERR;
}
