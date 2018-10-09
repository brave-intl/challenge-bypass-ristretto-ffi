#include "wrapper.hpp"

extern "C" {
#include "lib.h"
}

TokenPreimage::~TokenPreimage() { token_preimage_destroy(raw); }


Token::Token() {
  raw = token_generate();
  if (raw == nullptr) {
    throw "Failed to generate random token";
  }
}

Token::~Token() { token_destroy(raw); }

BlindedToken Token::blind() {
  void *raw_blinded = token_blind(raw);
  if (raw_blinded == nullptr) {
    throw "Failed to blind, is token valid?";
  }

  return BlindedToken(raw_blinded);
}

UnblindedToken Token::unblind(SignedToken tok) {
  void *raw_unblinded = token_unblind(raw, tok.raw);
  if (raw_unblinded == nullptr) {
    throw "Failed to unblind, are inputs valid?";
  }

  return UnblindedToken(raw_unblinded);
}



BlindedToken::~BlindedToken() { blinded_token_destroy(raw); }

BlindedToken decode_blinded_token(const std::string encoded) { 
  void* raw_blinded = blinded_token_decode(encoded.c_str());
  if (raw_blinded == nullptr) {
    throw "Failed to decode";
  }
  return BlindedToken(raw_blinded);
}

std::string BlindedToken::encode() { 
  char* tmp = blinded_token_encode(raw);
  std::string result = std::string(tmp);
  c_char_destroy(tmp);
  return result;
}


SignedToken::~SignedToken() { signed_token_destroy(raw); }


VerificationSignature::~VerificationSignature() { verification_signature_destroy(raw); }
bool VerificationSignature::equals(VerificationSignature sig) {
  return verification_signature_equals(raw, sig.raw);
}



UnblindedToken::~UnblindedToken() { unblinded_token_destroy(raw); }
VerificationKey UnblindedToken::derive_verification_key() {
  void *raw_verification_key = unblinded_token_derive_verification_key_sha512(raw);
  if (raw_verification_key == nullptr) {
    throw "Failed to derive verification key, are inputs valid?";
  }

  return VerificationKey(raw_verification_key);
}
TokenPreimage UnblindedToken::preimage() {
  void *raw_preimage = unblinded_token_preimage(raw);
  if (raw_preimage == nullptr) {
    throw "Failed to get preimage, are inputs valid?";
  }

  return TokenPreimage(raw_preimage);
}

VerificationKey::~VerificationKey() { verification_key_destroy(raw); }
VerificationSignature VerificationKey::sign(const std::string message) {
  void *raw_verification_signature = verification_key_sign_sha512(raw, message.c_str());
  if (raw_verification_signature == nullptr) {
    throw "Invalid message";
  }
  return VerificationSignature(raw_verification_signature);
}

SigningKey::SigningKey() {
  raw = signing_key_generate();
  if (raw == nullptr) {
    throw "Failed to generate random signing key";
  }
}

SigningKey::~SigningKey() { signing_key_destroy(raw); }

SignedToken SigningKey::sign(BlindedToken tok) {
  void *raw_signed = signing_key_sign(raw, tok.raw);
  if (raw_signed == nullptr) {
    throw "Failed to sign, are inputs valid?";
  }

  return SignedToken(raw_signed);
}

UnblindedToken SigningKey::rederive_unblinded_token(TokenPreimage t) {
  void *raw_unblinded = signing_key_rederive_unblinded_token(raw, t.raw);
  if (raw_unblinded == nullptr) {
    throw "Failed to rederive, are inputs valid?";
  }

  return UnblindedToken(raw_unblinded);
}
