#include <global.h>
#include <md5.h>
#include "digcal.h"
#include <string.h>

void CvtHex(IN HASH Bin,OUT HASHHEX Hex){
	unsigned short i;
	unsigned char j;
	for(i = 0; i<HASHLEN; i++) {
		j = (Bin[i]>>4) & 0xf;
		if(j <= 9) {
			Hex[i*2] = (j+'0');
		} else {
			Hex[i*2] = (j+'a'-10);
		} 
		j = Bin[i] & 0xf;
		if(j <= 9) {
			Hex[i*2+1] = (j+'0');
		} else {
			Hex[i*2+1] = (j+'a'-10);
		}
		Hex[HASHHEXLEN] = '\0';
	}
}

void DigestCalH_A1(
		IN char *pszAlg,
		IN char *pszUser,
		IN char *pszRealm,
		IN char *pszPswd,
		IN char *pszNonce, 
		IN char *pszClNonce,
		OUT HASHHEX SessionKey
		){
	//create md5_ctx structure-variable
	MD5_CTX Md5Ctx;
	//hash array
	HASH HA1;
	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx,pszUser,strlen(pszUser));
	MD5Update(&Md5Ctx,":",1);
	MD5Update(&Md5Ctx,pszRealm,strlen(pszRealm));
	MD5Update(&Md5Ctx,":",1);
	MD5Update(&Md5Ctx,pszPswd,strlen(pszPswd));
	MD5Update(&Md5Ctx,":",1);
	MD5Final(HA1, &Md5Ctx);
	
	if(strcasecmp(pszAlg,"md5-sess") == 0) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx,HA1,HASHLEN);
		MD5Update(&Md5Ctx,":",1);
		MD5Update(&Md5Ctx,pszNonce,strlen(pszNonce));
		MD5Update(&Md5Ctx,":",1);
		MD5Update(&Md5Ctx,pszClNonce,strlen(pszClNonce));
		MD5Final(HA1, &Md5Ctx);
	}
	CvtHex(HA1, SessionKey);
}

void DigestCalRespon(
		IN HASHLEN HA1,
		IN char *pszNonce,
		IN char *pszNonceCount,
		IN char *pszCNonce,
		IN char *pszQop,
		IN char *pszMethod,
		IN char *pszDigestUri,
		IN HASHLEN HEntity,
		OUT HASHHEX Response
		) {
	MD5_CTX Md5Ctx;
	HASH HA2;
	HASH RespHash;
	
	HASHHEX HA2Hex;
	//calculate H(A2)
	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, pszMethod, strlen(pszMethod));
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, pszDigestUri, strlen(pszDigestUri));
	if(strcasecmp(pszQop,"auth-int") == 0) {
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
	}
	MD5Final(HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);
	//response
	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, HA1, HASHHEXLEN);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
	MD5Update(&Md5Ctx, ":", 1);
	if(*pszQop) {
		MD5Update(&Md5Ctx,pszNonceCount,strlen(pszNonceCount));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, pszClNonce, strlen(pszClNonce));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, pszQop, strlen(pszQop));
		MD5Update(&Md5Ctx, ":", 1);
	}
	MD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
	MD5Final(RespHash, &Md5Ctx);
	CvtHex(RespHash, Response);
}
