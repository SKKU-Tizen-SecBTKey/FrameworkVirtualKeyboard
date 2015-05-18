


#include <stdio.h>  
#include <gmp.h> 
  
struct dh_key {  
    mpz_t p;  
    mpz_t g;  
    mpz_t priv_key;  
    mpz_t pub_key;  
    mpz_t compute_key;  
};  
  
void dh_init(dh_key* key)  
{  
    mpz_init(key->p);  
    mpz_init(key->g);  
    mpz_init(key->priv_key);  
    mpz_init(key->pub_key);  
    mpz_init(key->compute_key);  
}  
  
void dh_clear(dh_key* key)  
{  
    mpz_clear(key->p);  
    mpz_clear(key->g);  
    mpz_clear(key->priv_key);  
    mpz_clear(key->pub_key);  
    mpz_clear(key->compute_key);  
}  
  
int test_keyExchange()  
{  
    dh_key alice;  
    dh_key bob;  
  
    dh_init(&alice);  
    dh_init(&bob);  
  
    // set prime number  
    mpz_set_str(alice.p, "24523450234059872340587239408572495", 10);  
    mpz_set_str(bob.p, "24523450234059872340587239408572495", 10);  
  
    // set generator  
    mpz_set_ui(alice.g, 2);  
    mpz_set_ui(bob.g, 2);  
  
    // set private key  
    mpz_set_ui(alice.priv_key, 89148723);  
    mpz_set_ui(bob.priv_key, 1059234);  
  
  
    // calc public key  
    mpz_powm(alice.pub_key, alice.g, alice.priv_key, alice.p);  
    mpz_powm(bob.pub_key, bob.g, bob.priv_key, bob.p);  
  
    // calc compute key  
    mpz_powm(alice.compute_key, bob.pub_key, alice.priv_key, alice.p);  
    mpz_powm(bob.compute_key, alice.pub_key, bob.priv_key, bob.p);  
  
  
    // alice.compute_key == bob.compute_key  
    gmp_printf("alice compute key: %Zd\n", alice.compute_key);  
    gmp_printf("bob compute key: %Zd\n", bob.compute_key);  
  
  
    dh_clear(&alice);  
    dh_clear(&bob);  
    return 0;  
}  