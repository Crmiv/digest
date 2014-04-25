#define HASHLEN 16
#define HASHHEXLEN 32
#define IN
#define OUT

typedef char HASH[HASHLEN];
typedef char HASHHEX[HASHHEXLEN];

void DigestCalH_A1(
		IN char *pszAlg,
		IN char *pszUser,
		IN char *pszRealm,
		IN char *pszPswd,
		IN char *pszNonce, 
		IN char *pszClNonce,
		OUT HASHHEX SessionKey
		);

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
		);



