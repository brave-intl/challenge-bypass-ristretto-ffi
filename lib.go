package challenge_bypass_ristretto_ffi

/*
#cgo LDFLAGS: -L target/x86_64-unknown-linux-musl/debug -lchallenge_bypass_ristretto
#include "src/lib.h"
*/
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

type TokenPreimage struct {
	raw unsafe.Pointer
}

func token_preimage_finalizer(t *TokenPreimage) {
	C.token_preimage_destroy(t.raw)
	t.raw = nil
}

type Token struct {
	raw unsafe.Pointer
}

func token_finalizer(t *Token) {
	C.token_destroy(t.raw)
	t.raw = nil
}

func GenerateToken() (*Token, error) {
	raw := C.token_generate()
	if raw == nil {
		return nil, errors.New("Failed to generate token")
	}
	tok := &Token{raw: raw}
	runtime.SetFinalizer(tok, token_finalizer)
	return tok, nil
}

func (t *Token) Blind() (*BlindedToken, error) {
	raw := C.token_blind(t.raw)
	if raw == nil {
		return nil, errors.New("Failed to blind token")
	}
	tok := &BlindedToken{raw: raw}
	runtime.SetFinalizer(tok, blinded_token_finalizer)
	return tok, nil
}

func (t *Token) Unblind(st *SignedToken) (*UnblindedToken, error) {
	raw := C.token_unblind(t.raw, st.raw)
	if raw == nil {
		return nil, errors.New("Failed to unblind token")
	}
	tok := &UnblindedToken{raw: raw}
	runtime.SetFinalizer(tok, unblinded_token_finalizer)
	return tok, nil
}

type BlindedToken struct {
	raw unsafe.Pointer
}

func blinded_token_finalizer(t *BlindedToken) {
	C.blinded_token_destroy(t.raw)
	t.raw = nil
}

// MarshalText marshalls the blinded token into text.
func (t *BlindedToken) MarshalText() ([]byte, error) {
	encoded := C.blinded_token_encode(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode blinded token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the blinded token from text.
func (t *BlindedToken) UnmarshalText(text []byte) error {
	raw := C.blinded_token_decode(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decoded blinded token")
	}
	*t = BlindedToken{raw: raw}
	runtime.SetFinalizer(t, blinded_token_finalizer)
	return nil
}

type SignedToken struct {
	raw unsafe.Pointer
}

func signed_token_finalizer(t *SignedToken) {
	C.signed_token_destroy(t.raw)
	t.raw = nil
}

type SigningKey struct {
	raw unsafe.Pointer
}

func signing_key_finalizer(k *SigningKey) {
	C.signing_key_destroy(k.raw)
	k.raw = nil
}

func (k *SigningKey) Sign(t *BlindedToken) (*SignedToken, error) {
	raw := C.signing_key_sign(k.raw, t.raw)
	if raw == nil {
		return nil, errors.New("Failed to sign token")
	}
	tok := &SignedToken{raw: raw}
	runtime.SetFinalizer(tok, signed_token_finalizer)
	return tok, nil
}

func (k *SigningKey) RederiveUnblindedToken(t *TokenPreimage) (*UnblindedToken, error) {
	raw := C.signing_key_rederive_unblinded_token(k.raw, t.raw)
	if raw == nil {
		return nil, errors.New("Failed to rederive unblinded token")
	}
	tok := &UnblindedToken{raw: raw}
	runtime.SetFinalizer(tok, unblinded_token_finalizer)
	return tok, nil
}

func GenerateSigningKey() (*SigningKey, error) {
	raw := C.signing_key_generate()
	if raw == nil {
		return nil, errors.New("Failed to generate signing key")
	}
	key := &SigningKey{raw: raw}
	runtime.SetFinalizer(key, signing_key_finalizer)
	return key, nil
}

type UnblindedToken struct {
	raw unsafe.Pointer
}

func unblinded_token_finalizer(t *UnblindedToken) {
	C.unblinded_token_destroy(t.raw)
	t.raw = nil
}

func (t *UnblindedToken) DeriveVerificationKey() (*VerificationKey, error) {
	raw := C.unblinded_token_derive_verification_key_sha512(t.raw)
	if raw == nil {
		return nil, errors.New("Failed to derive verification key")
	}
	key := &VerificationKey{raw: raw}
	runtime.SetFinalizer(key, verification_key_finalizer)
	return key, nil
}

func (t *UnblindedToken) Preimage() (*TokenPreimage, error) {
	raw := C.unblinded_token_preimage(t.raw)
	if raw == nil {
		return nil, errors.New("Failed to get preimage")
	}
	tok := &TokenPreimage{raw: raw}
	runtime.SetFinalizer(tok, token_preimage_finalizer)
	return tok, nil
}

type VerificationKey struct {
	raw unsafe.Pointer
}

func verification_key_finalizer(k *VerificationKey) {
	C.verification_key_destroy(k.raw)
	k.raw = nil
}

func (k *VerificationKey) Sign(message string) (*VerificationSignature, error) {
	raw := C.verification_key_sign_sha512(k.raw, C.CString(message))
	if raw == nil {
		return nil, errors.New("Failed to sign message")
	}
	sig := &VerificationSignature{raw: raw}
	runtime.SetFinalizer(sig, verification_signature_finalizer)
	return sig, nil
}

type VerificationSignature struct {
	raw unsafe.Pointer
}

func verification_signature_finalizer(s *VerificationSignature) {
	C.verification_signature_destroy(s.raw)
	s.raw = nil
}

func (s1 *VerificationSignature) Equals(s2 *VerificationSignature) bool {
	return bool(C.verification_signature_equals(s1.raw, s2.raw))
}
