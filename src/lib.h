#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * A `BlindedToken` is sent to the server for signing.
 *
 * It is the result of the scalar multiplication of the point derived from the token
 * preimage with the blinding factor.
 *
 * \\(P = T^r = H_1(t)^r\\)
 */
typedef struct C_BlindedToken C_BlindedToken;

/*
 * A `SignedToken` is the result of signing an `BlindedToken`.
 *
 * \\(Q = P^k = (T^r)^k\\)
 */
typedef struct C_SignedToken C_SignedToken;

/*
 * A `SigningKey` is used to sign a `BlindedToken` and verify an `UnblindedToken`.
 *
 * This is a server secret and should NEVER be revealed to the client.
 */
typedef struct C_SigningKey C_SigningKey;

/*
 * A `Token` consists of a randomly chosen preimage and blinding factor.
 *
 * Since a token includes the blinding factor it should be treated
 * as a client secret and NEVER revealed to the server.
 */
typedef struct C_Token C_Token;

/*
 * A `TokenPreimage` is a slice of bytes which can be hashed to a `RistrettoPoint`.
 *
 * The hash function must ensure the discrete log with respect to other points is unknown.
 * In this construction `RistrettoPoint::from_uniform_bytes` is used as the hash function.
 */
typedef struct C_TokenPreimage C_TokenPreimage;

/*
 * An `UnblindedToken` is the result of unblinding a `SignedToken`.
 *
 * While both the client and server both "know" this value,
 * it should nevertheless not be sent between the two.
 */
typedef struct C_UnblindedToken C_UnblindedToken;

/*
 * The shared `VerificationKey` for proving / verifying the validity of an `UnblindedToken`.
 *
 * \\(K = H_2(t, W)\\)
 */
typedef struct C_VerificationKey C_VerificationKey;

/*
 * A `VerificationSignature` which can be verified given the `VerificationKey` and message
 */
typedef struct C_VerificationSignature C_VerificationSignature;

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_BlindedToken *blinded_token_decode_base64(const char *s);

/*
 * Destroy a `BlindedToken` once you are done with it.
 */
void blinded_token_destroy(C_BlindedToken *token);

/*
 * Return base64 encoding as a C string.
 */
char *blinded_token_encode_base64(const C_BlindedToken *t);

/*
 * Destroy a `*c_char` once you are done with it.
 */
void c_char_destroy(char *s);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_SignedToken *signed_token_decode_base64(const char *s);

/*
 * Destroy a `SignedToken` once you are done with it.
 */
void signed_token_destroy(C_SignedToken *token);

/*
 * Return base64 encoding as a C string.
 */
char *signed_token_encode_base64(const C_SignedToken *t);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_SigningKey *signing_key_decode_base64(const char *s);

/*
 * Destroy a `SigningKey` once you are done with it.
 */
void signing_key_destroy(C_SigningKey *key);

/*
 * Return base64 encoding as a C string.
 */
char *signing_key_encode_base64(const C_SigningKey *t);

/*
 * Generate a new `SigningKey`
 *
 * # Safety
 *
 * Make sure you destroy the key with [`signing_key_destroy()`] once you are
 * done with it.
 */
C_SigningKey *signing_key_random(void);

/*
 * Take a reference to a `SigningKey` and use it to rederive an `UnblindedToken`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `UnblindedToken` once you are done with it!
 */
C_UnblindedToken *signing_key_rederive_unblinded_token(const C_SigningKey *key,
                                                       const C_TokenPreimage *t);

/*
 * Take a reference to a `SigningKey` and use it to sign a `BlindedToken`, returning a
 * `SignedToken`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `SignedToken` once you are done with it!
 */
C_SignedToken *signing_key_sign(const C_SigningKey *key, const C_BlindedToken *token);

/*
 * Take a reference to a `Token` and blind it, returning a `BlindedToken`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `BlindedToken` once you are done with it!
 */
C_BlindedToken *token_blind(const C_Token *token);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_Token *token_decode_base64(const char *s);

/*
 * Destroy a `Token` once you are done with it.
 */
void token_destroy(C_Token *token);

/*
 * Return base64 encoding as a C string.
 */
char *token_encode_base64(const C_Token *t);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_TokenPreimage *token_preimage_decode_base64(const char *s);

/*
 * Destroy a `TokenPreimage` once you are done with it.
 */
void token_preimage_destroy(C_TokenPreimage *t);

/*
 * Return base64 encoding as a C string.
 */
char *token_preimage_encode_base64(const C_TokenPreimage *t);

/*
 * Generate a new `Token`
 *
 * # Safety
 *
 * Make sure you destroy the token with [`token_destroy()`] once you are
 * done with it.
 */
C_Token *token_random(void);

/*
 * Take a reference to a `Token` and use it to unblind a `SignedToken`, returning an `UnblindedToken`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `UnblindedToken` once you are done with it!
 */
C_UnblindedToken *token_unblind(const C_Token *token,
                                const C_SignedToken *signed_token);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_UnblindedToken *unblinded_token_decode_base64(const char *s);

/*
 * Take a reference to an `UnblindedToken` and use it to derive a `VerificationKey`
 * using Sha512 as the hash function
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `VerificationKey` once you are done with it!
 */
C_VerificationKey *unblinded_token_derive_verification_key_sha512(const C_UnblindedToken *token);

/*
 * Destroy an `UnblindedToken` once you are done with it.
 */
void unblinded_token_destroy(C_UnblindedToken *token);

/*
 * Return base64 encoding as a C string.
 */
char *unblinded_token_encode_base64(const C_UnblindedToken *t);

/*
 * Take a reference to an `UnblindedToken` and return the corresponding `TokenPreimage`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `BlindedToken` once you are done with it!
 */
C_TokenPreimage *unblinded_token_preimage(const C_UnblindedToken *token);

/*
 * Destroy a `VerificationKey` once you are done with it.
 */
void verification_key_destroy(C_VerificationKey *key);

/*
 * Take a reference to a `VerificationKey` and use it to sign a message
 * using Sha512 as the HMAC hash function to obtain a `VerificationSignature`
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the `VerificationSignature` once you are done with it!
 */
C_VerificationSignature *verification_key_sign_sha512(const C_VerificationKey *key,
                                                      const char *message);

/*
 * Take a reference to a `VerificationKey` and use it to verify an
 * existing `VerificationSignature` using Sha512 as the HMAC hash function
 *
 */
bool verification_key_verify_sha512(const C_VerificationKey *key,
                                    const C_VerificationSignature *sig,
                                    const char *message);

/*
 * Decode base64 C string.
 *
 * If something goes wrong, this will return a null pointer. Don't forget to
 * destroy the returned pointer once you are done with it!
 */
C_VerificationSignature *verification_signature_decode_base64(const char *s);

/*
 * Destroy a `VerificationSignature` once you are done with it.
 */
void verification_signature_destroy(C_VerificationSignature *sig);

/*
 * Return base64 encoding as a C string.
 */
char *verification_signature_encode_base64(const C_VerificationSignature *t);
