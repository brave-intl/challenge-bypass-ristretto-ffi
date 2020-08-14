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
#cgo LDFLAGS: -L target/x86_64-unknown-linux-musl/debug -lchallenge_bypass_ristretto_ffi
#include "src/lib.h"
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/pkg/errors"
)

// noCopy is embedded into structs which must not be copied.
// Copying a struct with embedded noCopy will result in a `go vet` error.
//
// See https://github.com/golang/go/issues/8005
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func wrapLastError(msg string) error {
	orig := C.last_error_message()
	if orig == nil {
		return errors.New(msg)
	}
	defer C.c_char_destroy(orig)
	return errors.Wrap(errors.New(C.GoString(orig)), msg)
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.token_preimage_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode token preimage")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the token preimage from text.
func (t *TokenPreimage) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_preimage_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode token preimage")
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_random()
	if raw == nil {
		return nil, wrapLastError("Failed to generate token")
	}
	tok := &Token{raw: raw}
	runtime.SetFinalizer(tok, tokenFinalizer)
	return tok, nil
}

// Blind the Token, returning a BlindedToken to be sent to the server.
func (t *Token) Blind() *BlindedToken {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_blind(t.raw)
	if raw == nil {
		panic(wrapLastError("Failed to blind token"))
	}
	tok := &BlindedToken{raw: raw}
	runtime.SetFinalizer(tok, blindedTokenFinalizer)
	return tok
}

// MarshalText marshalls the token into text.
func (t *Token) MarshalText() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.token_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the token from text.
func (t *Token) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.token_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode token")
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.blinded_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode blinded token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the blinded token from text.
func (t *BlindedToken) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.blinded_token_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decoded blinded token")
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.signed_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode signed token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the signed token from text.
func (t *SignedToken) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signed_token_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode signed token")
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
		return nil, wrapLastError("Failed to sign token")
	}
	tok := &SignedToken{raw: raw}
	runtime.SetFinalizer(tok, signedTokenFinalizer)
	return tok, nil
}

// RederiveUnblindedToken via the token preimage of the provided UnblindedToken
func (k *SigningKey) RederiveUnblindedToken(t *TokenPreimage) *UnblindedToken {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_rederive_unblinded_token(k.raw, t.raw)
	if raw == nil {
		panic(wrapLastError("Failed to rederive unblinded token"))
	}
	tok := &UnblindedToken{raw: raw}
	runtime.SetFinalizer(tok, unblindedTokenFinalizer)
	return tok
}

// RandomSigningKey generates a new random `SigningKey` using the os random number generator.
func RandomSigningKey() (*SigningKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_random()
	if raw == nil {
		return nil, wrapLastError("Failed to generate signing key")
	}
	key := &SigningKey{raw: raw}
	runtime.SetFinalizer(key, signingKeyFinalizer)
	return key, nil
}

// MarshalText marshalls the signing key into text.
func (k *SigningKey) MarshalText() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.signing_key_encode_base64(k.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode signing key")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the signing key from text.
func (k *SigningKey) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode signing key")
	}
	*k = SigningKey{raw: raw}
	runtime.SetFinalizer(k, signingKeyFinalizer)
	return nil
}

// PublicKey returns the public key associated with this SigningKey
func (k *SigningKey) PublicKey() *PublicKey {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.signing_key_get_public_key(k.raw)
	if raw == nil {
		panic(wrapLastError("Failed to get public key for signing key"))
	}
	pub := &PublicKey{raw: raw}
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
func (t *UnblindedToken) DeriveVerificationKey() *VerificationKey {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.unblinded_token_derive_verification_key_sha512(t.raw)
	if raw == nil {
		panic(wrapLastError("Failed to derive verification key"))
	}
	key := &VerificationKey{raw: raw}
	runtime.SetFinalizer(key, verificationKeyFinalizer)
	return key
}

// Preimage returns the TokenPreimage for this particular UnblindedToken
func (t *UnblindedToken) Preimage() *TokenPreimage {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.unblinded_token_preimage(t.raw)
	if raw == nil {
		panic(wrapLastError("Failed to get token preimage for unblinded token"))
	}
	tok := &TokenPreimage{raw: raw}
	runtime.SetFinalizer(tok, tokenPreimageFinalizer)
	return tok
}

// MarshalText marshalls the unblinded token into text.
func (t *UnblindedToken) MarshalText() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.unblinded_token_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode unblinded token")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *UnblindedToken) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.unblinded_token_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode unblinded token")
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

	bytes := []byte(message)
	raw := C.verification_key_sign_sha512(k.raw, (*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))
	if raw == nil {
		return nil, wrapLastError("Failed to sign message")
	}
	sig := &VerificationSignature{raw: raw}
	runtime.SetFinalizer(sig, verificationSignatureFinalizer)
	return sig, nil
}

// Verify that the signature of a message matches the provided `VerificationSignature`
func (k *VerificationKey) Verify(sig *VerificationSignature, message string) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bytes := []byte(message)
	result := C.verification_key_invalid_sha512(k.raw, sig.raw, (*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))
	if result < 0 {
		return false, wrapLastError("Failed to verify message signature")
	}
	return result == 0, nil
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.verification_signature_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode verification signature")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *VerificationSignature) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.verification_signature_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode verification signature")
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.public_key_encode_base64(t.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode public key")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (t *PublicKey) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.public_key_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode public key")
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
		return nil, wrapLastError("Failed to create new DLEQ proof")
	}
	proof := &DLEQProof{raw: raw}
	runtime.SetFinalizer(proof, dleqProofFinalizer)
	return proof, nil
}

// Verify that the DLEQProof shows the SignedToken is BlindedToken signed by the same SigningKey as PublicKey
func (proof *DLEQProof) Verify(blindedToken *BlindedToken, signedToken *SignedToken, publicKey *PublicKey) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := C.dleq_proof_invalid(proof.raw, blindedToken.raw, signedToken.raw, publicKey.raw)
	if result < 0 {
		return false, wrapLastError("Failed to verify DLEQ proof")
	}
	return result == 0, nil
}

// MarshalText marshalls the verification signature into text.
func (proof *DLEQProof) MarshalText() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.dleq_proof_encode_base64(proof.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode DLEQ proof")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (proof *DLEQProof) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.dleq_proof_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode DLEQ proof")
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
		return nil, wrapLastError("Failed to create new DLEQ proof")
	}
	proof := &BatchDLEQProof{raw: raw}
	runtime.SetFinalizer(proof, batchDleqProofFinalizer)
	return proof, nil
}

// Verify that the BatchDLEQProof shows each SignedToken is a BlindedToken signed by the same SigningKey as PublicKey
func (proof *BatchDLEQProof) Verify(blindedTokens []*BlindedToken, signedTokens []*SignedToken, publicKey *PublicKey) (bool, error) {
	if len(blindedTokens) != len(signedTokens) {
		return false, errors.New("Blinded tokens and signed tokens must have same length")
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

	result := C.batch_dleq_proof_invalid(proof.raw,
		(**C.C_BlindedToken)(unsafe.Pointer(&cBlindedTokens[0])),
		(**C.C_SignedToken)(unsafe.Pointer(&cSignedTokens[0])),
		C.int(len(cBlindedTokens)), publicKey.raw)

	if result < 0 {
		return false, wrapLastError("Error duing batch DLEQ proof verification")
	}
	return result == 0, nil
}

// VerifyAndUnblind each SignedToken if the BatchDLEQProof is valid
func (proof *BatchDLEQProof) VerifyAndUnblind(tokens []*Token, blindedTokens []*BlindedToken, signedTokens []*SignedToken, publicKey *PublicKey) ([]*UnblindedToken, error) {
	if len(tokens) != len(signedTokens) || len(blindedTokens) != len(signedTokens) {
		return nil, errors.New("Blinded tokens and signed tokens must have same length")
	}

	cTokens := make([]*C.C_Token, len(tokens), len(tokens))
	for k, v := range tokens {
		cTokens[k] = v.raw
	}
	cBlindedTokens := make([]*C.C_BlindedToken, len(blindedTokens), len(blindedTokens))
	for k, v := range blindedTokens {
		cBlindedTokens[k] = v.raw
	}
	cSignedTokens := make([]*C.C_SignedToken, len(signedTokens), len(signedTokens))
	for k, v := range signedTokens {
		cSignedTokens[k] = v.raw
	}
	cUnblindedTokens := make([]*C.C_UnblindedToken, len(tokens), len(tokens))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := C.batch_dleq_proof_invalid_or_unblind(proof.raw,
		(**C.C_Token)(unsafe.Pointer(&cTokens[0])),
		(**C.C_BlindedToken)(unsafe.Pointer(&cBlindedTokens[0])),
		(**C.C_SignedToken)(unsafe.Pointer(&cSignedTokens[0])),
		(**C.C_UnblindedToken)(unsafe.Pointer(&cUnblindedTokens[0])),
		C.int(len(cBlindedTokens)), publicKey.raw)

	if result < 0 {
		return nil, wrapLastError("Error duing batch DLEQ proof verification")
	} else if result > 0 {
		return nil, errors.New("Invalid proof")
	}

	unblindedTokens := make([]*UnblindedToken, len(tokens), len(tokens))
	for k, v := range cUnblindedTokens {
		unblindedTokens[k] = &UnblindedToken{raw: v}
		runtime.SetFinalizer(unblindedTokens[k], unblindedTokenFinalizer)
	}

	return unblindedTokens, nil
}

// MarshalText marshalls the verification signature into text.
func (proof *BatchDLEQProof) MarshalText() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	encoded := C.batch_dleq_proof_encode_base64(proof.raw)
	if encoded == nil {
		return nil, wrapLastError("Failed to encode batch DLEQ proof")
	}
	defer C.c_char_destroy(encoded)
	return []byte(C.GoString(encoded)), nil
}

// UnmarshalText unmarshalls the unblinded token from text.
func (proof *BatchDLEQProof) UnmarshalText(bytes []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	raw := C.batch_dleq_proof_decode_base64((*C.uint8_t)(&bytes[0]), C.size_t(len(bytes)))

	if raw == nil {
		return wrapLastError("Failed to decode batch DLEQ proof")
	}
	*proof = BatchDLEQProof{raw: raw}
	runtime.SetFinalizer(proof, batchDleqProofFinalizer)
	return nil
}
