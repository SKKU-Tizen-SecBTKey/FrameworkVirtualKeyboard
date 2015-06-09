#ifndef _KEYEXCHANGE_H_INCLUDED_
#define _KEYEXCHANGE_H_INCLUDED_

#ifdef __cplusplus
extern "C"
{
#endif

void secure_key_exchange(const char* p, int g);

const char* secure_find_key(const char* eBob);

void secure_aes_cbc_init(void);

const char* secure_aes_cbc_decrypt(const char *cipherText64);

void secure_aes_cbc_dispose(void);

#ifdef __cplusplus
}
#endif

#endif /* _KEYEXCHANGE_H_INCLUDED_ */
