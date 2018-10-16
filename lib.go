package challenge_bypass_ristretto_ffi

/*
#cgo LDFLAGS: -L target/x86_64-unknown-linux-musl/debug -lchallenge_bypass_ristretto
#include "src/lib.h"
*/
import "C"
import (
	"errors"
	"runtime"
)

type TokenPreimage struct {
	raw *C.C_TokenPreimage
}

func token_preimage_finalizer(t *TokenPreimage) {
	C.token_preimage_destroy(t.raw)
}

// MarshalText marshalls the token preimage into text.
func (t *TokenPreimage) MarshalText() ([]byte, error) {
	encoded := C.token_preimage_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode token preimage")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the token preimage from text.
func (t *TokenPreimage) UnmarshalText(text []byte) error {
	raw := C.token_preimage_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode token preimage")
	}
	*t = TokenPreimage{raw: raw}
	runtime.SetFinalizer(t, token_preimage_finalizer)
	return nil
}

type Token struct {
	raw *C.C_Token
}

func token_finalizer(t *Token) {
	C.token_destroy(t.raw)
	t.raw = nil
}

func RandomToken() (*Token, error) {
	raw := C.token_random()
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

// MarshalText marshalls the token into text.
func (t *Token) MarshalText() ([]byte, error) {
	encoded := C.token_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the token from text.
func (t *Token) UnmarshalText(text []byte) error {
	raw := C.token_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode token")
	}
	*t = Token{raw: raw}
	runtime.SetFinalizer(t, token_finalizer)
	return nil
}

type BlindedToken struct {
	raw *C.C_BlindedToken
}

func blinded_token_finalizer(t *BlindedToken) {
	C.blinded_token_destroy(t.raw)
	t.raw = nil
}

// MarshalText marshalls the blinded token into text.
func (t *BlindedToken) MarshalText() ([]byte, error) {
	encoded := C.blinded_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode blinded token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the blinded token from text.
func (t *BlindedToken) UnmarshalText(text []byte) error {
	raw := C.blinded_token_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decoded blinded token")
	}
	*t = BlindedToken{raw: raw}
	runtime.SetFinalizer(t, blinded_token_finalizer)
	return nil
}

type SignedToken struct {
	raw *C.C_SignedToken
}

func signed_token_finalizer(t *SignedToken) {
	C.signed_token_destroy(t.raw)
	t.raw = nil
}

// MarshalText marshalls the signed token into text.
func (t *SignedToken) MarshalText() ([]byte, error) {
	encoded := C.signed_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode signed token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the signed token from text.
func (t *SignedToken) UnmarshalText(text []byte) error {
	raw := C.signed_token_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode signed token")
	}
	*t = SignedToken{raw: raw}
	runtime.SetFinalizer(t, signed_token_finalizer)
	return nil
}

type SigningKey struct {
	raw *C.C_SigningKey
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

func RandomSigningKey() (*SigningKey, error) {
	raw := C.signing_key_random()
	if raw == nil {
		return nil, errors.New("Failed to generate signing key")
	}
	key := &SigningKey{raw: raw}
	runtime.SetFinalizer(key, signing_key_finalizer)
	return key, nil
}

// MarshalText marshalls the signing key into text.
func (t *SigningKey) MarshalText() ([]byte, error) {
	encoded := C.signing_key_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode signing key")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the signing key from text.
func (t *SigningKey) UnmarshalText(text []byte) error {
	raw := C.signing_key_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode signing key")
	}
	*t = SigningKey{raw: raw}
	runtime.SetFinalizer(t, signing_key_finalizer)
	return nil
}

type UnblindedToken struct {
	raw *C.C_UnblindedToken
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

// MarshalText marshalls the unblinded token into text.
func (t *UnblindedToken) MarshalText() ([]byte, error) {
	encoded := C.unblinded_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode unblinded token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *UnblindedToken) UnmarshalText(text []byte) error {
	raw := C.unblinded_token_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode unblinded token")
	}
	*t = UnblindedToken{raw: raw}
	runtime.SetFinalizer(t, unblinded_token_finalizer)
	return nil
}

type VerificationKey struct {
	raw *C.C_VerificationKey
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

func (k *VerificationKey) Verify(sig *VerificationSignature, message string) bool {
	return bool(C.verification_key_verify_sha512(k.raw, sig.raw, C.CString(message)))
}

type VerificationSignature struct {
	raw *C.C_VerificationSignature
}

func verification_signature_finalizer(s *VerificationSignature) {
	C.verification_signature_destroy(s.raw)
	s.raw = nil
}

// MarshalText marshalls the verification signature into text.
func (t *VerificationSignature) MarshalText() ([]byte, error) {
	encoded := C.verification_signature_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode verification signature")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *VerificationSignature) UnmarshalText(text []byte) error {
	raw := C.verification_signature_decode_base64(C.CString(string(text)))
	if raw == nil {
		return errors.New("Failed to decode verification signature")
	}
	*t = VerificationSignature{raw: raw}
	runtime.SetFinalizer(t, verification_signature_finalizer)
	return nil
}
