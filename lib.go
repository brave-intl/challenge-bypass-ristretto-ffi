// A golang wrapper for challenge-bypass-ristretto
//
// NOTE all structs wrap raw C FFI pointers to memory allocated in rust.
//
// Finalizers to deallocate memory are assigned immediately following
// internal calls to any rust functions which allocate memory.
//
// As a result it is CRITICAL that you DO NOT COPY ANY STRUCT from this package.
//
// To help enforce this behavior, a "noCopy" struct has been embedded which will cause a
// `go vet` error if copied. Do yourself a favor and set up your favorite meta linter early.

package challengebypassristrettoffi

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

// noCopy is embedded into structs which must not be copied.
// Copying a struct with embedded noCopy will result in a `go vet` error.
//
// See https://github.com/golang/go/issues/8005
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func lastErrorOr(defaultMsg string) error {
	msg := C.last_error_message()
	defer C.c_char_destroy(msg)
	if msg == nil {
		return errors.New(defaultMsg)
	} else {
		return errors.New(C.GoString(msg))
	}
}

// TokenPreimage is a slice of bytes which can be hashed to a `RistrettoPoint`.
type TokenPreimage struct {
	raw    *C.C_TokenPreimage
	noCopy noCopy
}

func tokenPreimageFinalizer(t *TokenPreimage) {
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.token_preimage_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode token preimage")
	}
	*t = TokenPreimage{raw: raw}
	runtime.SetFinalizer(t, tokenPreimageFinalizer)
	return nil
}

// Token consists of a randomly chosen preimage and blinding factor.
type Token struct {
	raw    *C.C_Token
	noCopy noCopy
}

func tokenFinalizer(t *Token) {
	C.token_destroy(t.raw)
	t.raw = nil
}

// RandomToken generates a new random `Token` using the os random number generator.
func RandomToken() (*Token, error) {
	raw := C.token_random()
	if raw == nil {
		return nil, errors.New("Failed to generate token")
	}
	tok := &Token{raw: raw}
	runtime.SetFinalizer(tok, tokenFinalizer)
	return tok, nil
}

// Blind the Token, returning a BlindedToken to be sent to the server.
func (t *Token) Blind() (*BlindedToken, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_blind(t.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to blind token")
	}
	tok := &BlindedToken{raw: raw}
	runtime.SetFinalizer(tok, blindedTokenFinalizer)
	return tok, nil
}

// Unblind a SignedToken` using the blinding factor of the original Token
func (t *Token) Unblind(st *SignedToken) (*UnblindedToken, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_unblind(t.raw, st.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to unblind token")
	}
	tok := &UnblindedToken{raw: raw}
	runtime.SetFinalizer(tok, unblindedTokenFinalizer)
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.token_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode token")
	}
	*t = Token{raw: raw}
	runtime.SetFinalizer(t, tokenFinalizer)
	return nil
}

// BlindedToken is sent to the server for signing.
type BlindedToken struct {
	raw    *C.C_BlindedToken
	noCopy noCopy
}

func blindedTokenFinalizer(t *BlindedToken) {
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.blinded_token_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decoded blinded token")
	}
	*t = BlindedToken{raw: raw}
	runtime.SetFinalizer(t, blindedTokenFinalizer)
	return nil
}

//SignedToken is the result of signing a BlindedToken.
type SignedToken struct {
	raw    *C.C_SignedToken
	noCopy noCopy
}

func signedTokenFinalizer(t *SignedToken) {
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.signed_token_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode signed token")
	}
	*t = SignedToken{raw: raw}
	runtime.SetFinalizer(t, signedTokenFinalizer)
	return nil
}

// SigningKey is used to sign a BlindedToken and verify an UnblindedToken.
//
// This is a server secret and should NEVER be revealed to the client.
type SigningKey struct {
	raw    *C.C_SigningKey
	noCopy noCopy
}

func signingKeyFinalizer(k *SigningKey) {
	C.signing_key_destroy(k.raw)
	k.raw = nil
}

// Sign the provided BlindedToken.
func (k *SigningKey) Sign(t *BlindedToken) (*SignedToken, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_sign(k.raw, t.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to sign token")
	}
	tok := &SignedToken{raw: raw}
	runtime.SetFinalizer(tok, signedTokenFinalizer)
	return tok, nil
}

// RederiveUnblindedToken via the token preimage of the provided UnblindedToken
func (k *SigningKey) RederiveUnblindedToken(t *TokenPreimage) (*UnblindedToken, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_rederive_unblinded_token(k.raw, t.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to rederive unblinded token")
	}
	tok := &UnblindedToken{raw: raw}
	runtime.SetFinalizer(tok, unblindedTokenFinalizer)
	return tok, nil
}

// RandomSigningKey generates a new random `SigningKey` using the os random number generator.
func RandomSigningKey() (*SigningKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_random()
	if raw == nil {
		return nil, lastErrorOr("Failed to generate signing key")
	}
	key := &SigningKey{raw: raw}
	runtime.SetFinalizer(key, signingKeyFinalizer)
	return key, nil
}

// MarshalText marshalls the signing key into text.
func (k *SigningKey) MarshalText() ([]byte, error) {
	encoded := C.signing_key_encode_base64(k.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode signing key")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the signing key from text.
func (k *SigningKey) UnmarshalText(text []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.signing_key_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode signing key")
	}
	*k = SigningKey{raw: raw}
	runtime.SetFinalizer(k, signingKeyFinalizer)
	return nil
}

// PublicKey returns the public key associated with this SigningKey
func (k *SigningKey) PublicKey() *PublicKey {
	pub := &PublicKey{raw: C.signing_key_get_public_key(k.raw)}
	runtime.SetFinalizer(pub, publicKeyFinalizer)
	return pub
}

// UnblindedToken is the result of unblinding a SignedToken.
type UnblindedToken struct {
	raw    *C.C_UnblindedToken
	noCopy noCopy
}

func unblindedTokenFinalizer(t *UnblindedToken) {
	C.unblinded_token_destroy(t.raw)
	t.raw = nil
}

// DeriveVerificationKey for this particular UnblindedToken
func (t *UnblindedToken) DeriveVerificationKey() (*VerificationKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.unblinded_token_derive_verification_key_sha512(t.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to derive verification key")
	}
	key := &VerificationKey{raw: raw}
	runtime.SetFinalizer(key, verificationKeyFinalizer)
	return key, nil
}

// Preimage returns the TokenPreimage for this particular UnblindedToken
func (t *UnblindedToken) Preimage() *TokenPreimage {
	tok := &TokenPreimage{raw: C.unblinded_token_preimage(t.raw)}
	runtime.SetFinalizer(tok, tokenPreimageFinalizer)
	return tok
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.unblinded_token_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode unblinded token")
	}
	*t = UnblindedToken{raw: raw}
	runtime.SetFinalizer(t, unblindedTokenFinalizer)
	return nil
}

// VerificationKey is the shared key for proving / verifying the validity of an UnblindedToken.
type VerificationKey struct {
	raw    *C.C_VerificationKey
	noCopy noCopy
}

func verificationKeyFinalizer(k *VerificationKey) {
	C.verification_key_destroy(k.raw)
	k.raw = nil
}

// Sign a message, producing a VerificationSignature
func (k *VerificationKey) Sign(message string) (*VerificationSignature, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(message)
	defer C.free(unsafe.Pointer(cs))
	raw := C.verification_key_sign_sha512(k.raw, cs)
	if raw == nil {
		return nil, lastErrorOr("Failed to sign message")
	}
	sig := &VerificationSignature{raw: raw}
	runtime.SetFinalizer(sig, verificationSignatureFinalizer)
	return sig, nil
}

// Verify that the signature of a message matches the provided `VerificationSignature`
func (k *VerificationKey) Verify(sig *VerificationSignature, message string) bool {
	cs := C.CString(message)
	defer C.free(unsafe.Pointer(cs))
	return bool(C.verification_key_verify_sha512(k.raw, sig.raw, cs))
}

// VerificationSignature which can be verified given the VerificationKey and message
type VerificationSignature struct {
	raw    *C.C_VerificationSignature
	noCopy noCopy
}

func verificationSignatureFinalizer(s *VerificationSignature) {
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.verification_signature_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode verification signature")
	}
	*t = VerificationSignature{raw: raw}
	runtime.SetFinalizer(t, verificationSignatureFinalizer)
	return nil
}

// PublicKey is a committment by the server to a particular SigningKey.
type PublicKey struct {
	raw    *C.C_PublicKey
	noCopy noCopy
}

func publicKeyFinalizer(k *PublicKey) {
	C.public_key_destroy(k.raw)
	k.raw = nil
}

// MarshalText marshalls the verification signature into text.
func (t *PublicKey) MarshalText() ([]byte, error) {
	encoded := C.public_key_encode_base64(t.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode public key")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *PublicKey) UnmarshalText(text []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.public_key_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode public key")
	}
	*t = PublicKey{raw: raw}
	runtime.SetFinalizer(t, publicKeyFinalizer)
	return nil
}

// DLEQProof shows a point was signed by the same signing key as a particular PublicKey
type DLEQProof struct {
	raw    *C.C_DLEQProof
	noCopy noCopy
}

func dleqProofFinalizer(p *DLEQProof) {
	C.dleq_proof_destroy(p.raw)
	p.raw = nil
}

// NewDLEQProof showing SignedToken is the result of signing BlindedToken with the given SigningKey
func NewDLEQProof(blindedToken *BlindedToken, signedToken *SignedToken, key *SigningKey) (*DLEQProof, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.dleq_proof_new(blindedToken.raw, signedToken.raw, key.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to create new DLEQ proof")
	}
	proof := &DLEQProof{raw: raw}
	runtime.SetFinalizer(proof, dleqProofFinalizer)
	return proof, nil
}

// Verify that the DLEQProof shows the SignedToken is BlindedToken signed by the same SigningKey as PublicKey
func (proof *DLEQProof) Verify(blindedToken *BlindedToken, signedToken *SignedToken, publicKey *PublicKey) bool {
	return bool(C.dleq_proof_verify(proof.raw, blindedToken.raw, signedToken.raw, publicKey.raw))
}

// MarshalText marshalls the verification signature into text.
func (proof *DLEQProof) MarshalText() ([]byte, error) {
	encoded := C.dleq_proof_encode_base64(proof.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode DLEQ proof")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (proof *DLEQProof) UnmarshalText(text []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.dleq_proof_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode DLEQ proof")
	}
	*proof = DLEQProof{raw: raw}
	runtime.SetFinalizer(proof, dleqProofFinalizer)
	return nil
}

// BatchDLEQProof shows many points were signed by the same signing key as a particular PublicKey
type BatchDLEQProof struct {
	raw    *C.C_BatchDLEQProof
	noCopy noCopy
}

func batchDleqProofFinalizer(p *BatchDLEQProof) {
	C.batch_dleq_proof_destroy(p.raw)
	p.raw = nil
}

// NewBatchDLEQProof showing each SignedToken is the result of signing the corresponding BlindedToken with the
// given SigningKey
func NewBatchDLEQProof(blindedTokens []*BlindedToken, signedTokens []*SignedToken, key *SigningKey) (*BatchDLEQProof, error) {
	if len(blindedTokens) != len(signedTokens) {
		return nil, errors.New("Length of blinded and signed tokens must match")
	}

	cBlindedTokens := make([]*C.C_BlindedToken, len(blindedTokens), len(blindedTokens))
	for k, v := range blindedTokens {
		cBlindedTokens[k] = v.raw
	}
	cSignedTokens := make([]*C.C_SignedToken, len(signedTokens), len(signedTokens))
	for k, v := range signedTokens {
		cSignedTokens[k] = v.raw
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.batch_dleq_proof_new(
		(**C.C_BlindedToken)(unsafe.Pointer(&cBlindedTokens[0])),
		(**C.C_SignedToken)(unsafe.Pointer(&cSignedTokens[0])),
		C.int(len(cBlindedTokens)), key.raw)
	if raw == nil {
		return nil, lastErrorOr("Failed to create new DLEQ proof")
	}
	proof := &BatchDLEQProof{raw: raw}
	runtime.SetFinalizer(proof, batchDleqProofFinalizer)
	return proof, nil
}

// Verify that the BatchDLEQProof shows each SignedToken is a BlindedToken signed by the same SigningKey as PublicKey
func (proof *BatchDLEQProof) Verify(blindedTokens []*BlindedToken, signedTokens []*SignedToken, publicKey *PublicKey) bool {
	if len(blindedTokens) != len(signedTokens) {
		return false
	}

	cBlindedTokens := make([]*C.C_BlindedToken, len(blindedTokens), len(blindedTokens))
	for k, v := range blindedTokens {
		cBlindedTokens[k] = v.raw
	}
	cSignedTokens := make([]*C.C_SignedToken, len(signedTokens), len(signedTokens))
	for k, v := range signedTokens {
		cSignedTokens[k] = v.raw
	}

	return bool(C.batch_dleq_proof_verify(proof.raw,
		(**C.C_BlindedToken)(unsafe.Pointer(&cBlindedTokens[0])),
		(**C.C_SignedToken)(unsafe.Pointer(&cSignedTokens[0])),
		C.int(len(cBlindedTokens)), publicKey.raw))
}

// MarshalText marshalls the verification signature into text.
func (proof *BatchDLEQProof) MarshalText() ([]byte, error) {
	encoded := C.batch_dleq_proof_encode_base64(proof.raw)
	if encoded == nil {
		return nil, errors.New("Failed to encode batch DLEQ proof")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (proof *BatchDLEQProof) UnmarshalText(text []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := C.CString(string(text))
	defer C.free(unsafe.Pointer(cs))
	raw := C.batch_dleq_proof_decode_base64(cs)
	if raw == nil {
		return lastErrorOr("Failed to decode batch DLEQ proof")
	}
	*proof = BatchDLEQProof{raw: raw}
	runtime.SetFinalizer(proof, batchDleqProofFinalizer)
	return nil
}
