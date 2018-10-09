#ifndef _CHALLENGE_BYPASS_RISTRETTO_H
#define _CHALLENGE_BYPASS_RISTRETTO_H

#include <stdbool.h>

void token_preimage_destroy(void *);

void *token_generate();
void token_destroy(void *);
void *token_blind(void *);
void *token_unblind(void *, void *);

void blinded_token_destroy(void *);
char *blinded_token_encode(void *);
void *blinded_token_decode(const char *);

void c_char_destroy(char *);

void signed_token_destroy(void *);

void verification_signature_destroy(void *);
bool verification_signature_equals(void *, void *);

void unblinded_token_destroy(void *);
void *unblinded_token_derive_verification_key_sha512(void *);
void *unblinded_token_preimage(void *);

void verification_key_destroy(void *);
void *verification_key_sign_sha512(void *, const char *);

void *signing_key_generate();
void signing_key_destroy(void *);
void *signing_key_sign(void *, void *);
void *signing_key_rederive_unblinded_token(void *, void *);


#endif /* _CHALLENGE_BYPASS_RISTRETTO_H */
