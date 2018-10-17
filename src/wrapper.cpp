#include "wrapper.hpp"

extern "C" {
#include "lib.h"
}

// class TokenPreimage
namespace challenge_bypass_ristretto {
  TokenPreimage::~TokenPreimage() { token_preimage_destroy(raw); }

  TokenPreimage TokenPreimage::decode_base64(const std::string encoded) { 
    C_TokenPreimage *raw_preimage = token_preimage_decode_base64(encoded.c_str());
    if (raw_preimage == nullptr) {
      throw "Failed to decode";
    }
    return TokenPreimage(raw_preimage);
  }

  std::string TokenPreimage::encode_base64() { 
    char* tmp = token_preimage_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class Token
namespace challenge_bypass_ristretto {
  Token Token::random() {
    C_Token *raw_token = token_random();
    if (raw_token == nullptr) {
      throw "Failed to generate random token";
    }
    return Token(raw_token);
  }

  Token::~Token() { token_destroy(raw); }

  BlindedToken Token::blind() {
    C_BlindedToken *raw_blinded = token_blind(raw);
    if (raw_blinded == nullptr) {
      throw "Failed to blind, is token valid?";
    }

    return BlindedToken(raw_blinded);
  }

  UnblindedToken Token::unblind(SignedToken *tok) {
    C_UnblindedToken *raw_unblinded = token_unblind(raw, tok->raw);
    if (raw_unblinded == nullptr) {
      throw "Failed to unblind, are inputs valid?";
    }

    return UnblindedToken(raw_unblinded);
  }

  Token Token::decode_base64(const std::string encoded) { 
    C_Token *raw_tok = token_decode_base64(encoded.c_str());
    if (raw_tok == nullptr) {
      throw "Failed to decode";
    }
    return Token(raw_tok);
  }

  std::string Token::encode_base64() { 
    char* tmp = token_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class BlindedToken
namespace challenge_bypass_ristretto {
  BlindedToken::~BlindedToken() { blinded_token_destroy(raw); }

  BlindedToken BlindedToken::decode_base64(const std::string encoded) { 
    C_BlindedToken *raw_blinded = blinded_token_decode_base64(encoded.c_str());
    if (raw_blinded == nullptr) {
      throw "Failed to decode";
    }
    return BlindedToken(raw_blinded);
  }

  std::string BlindedToken::encode_base64() { 
    char* tmp = blinded_token_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class SignedToken
namespace challenge_bypass_ristretto {
  SignedToken::~SignedToken() { signed_token_destroy(raw); }

  SignedToken SignedToken::decode_base64(const std::string encoded) { 
    C_SignedToken *raw_signed = signed_token_decode_base64(encoded.c_str());
    if (raw_signed == nullptr) {
      throw "Failed to decode";
    }
    return SignedToken(raw_signed);
  }

  std::string SignedToken::encode_base64() { 
    char* tmp = signed_token_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class VerificationSignature
namespace challenge_bypass_ristretto {
  VerificationSignature::~VerificationSignature() { verification_signature_destroy(raw); }

  VerificationSignature VerificationSignature::decode_base64(const std::string encoded) { 
    C_VerificationSignature *raw_sig = verification_signature_decode_base64(encoded.c_str());
    if (raw_sig == nullptr) {
      throw "Failed to decode";
    }
    return VerificationSignature(raw_sig);
  }

  std::string VerificationSignature::encode_base64() { 
    char* tmp = verification_signature_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class UnblindedToken
namespace challenge_bypass_ristretto {
  UnblindedToken::~UnblindedToken() { unblinded_token_destroy(raw); }

  VerificationKey UnblindedToken::derive_verification_key() {
    C_VerificationKey *raw_verification_key = unblinded_token_derive_verification_key_sha512(raw);
    if (raw_verification_key == nullptr) {
      throw "Failed to derive verification key, are inputs valid?";
    }

    return VerificationKey(raw_verification_key);
  }

  TokenPreimage UnblindedToken::preimage() {
    C_TokenPreimage *raw_preimage = unblinded_token_preimage(raw);
    if (raw_preimage == nullptr) {
      throw "Failed to get preimage, are inputs valid?";
    }

    return TokenPreimage(raw_preimage);
  }

  UnblindedToken UnblindedToken::decode_base64(const std::string encoded) { 
    C_UnblindedToken *raw_unblinded = unblinded_token_decode_base64(encoded.c_str());
    if (raw_unblinded == nullptr) {
      throw "Failed to decode";
    }
    return UnblindedToken(raw_unblinded);
  }

  std::string UnblindedToken::encode_base64() { 
    char* tmp = unblinded_token_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class VerificationKey
namespace challenge_bypass_ristretto {
  VerificationKey::~VerificationKey() { verification_key_destroy(raw); }

  VerificationSignature VerificationKey::sign(const std::string message) {
    C_VerificationSignature *raw_verification_signature = verification_key_sign_sha512(raw, message.c_str());
    if (raw_verification_signature == nullptr) {
      throw "Invalid message";
    }
    return VerificationSignature(raw_verification_signature);
  }

  bool VerificationKey::verify(VerificationSignature *sig, const std::string message) {
    return verification_key_verify_sha512(raw, sig->raw, message.c_str());
  }
}

// class SigningKey
namespace challenge_bypass_ristretto {
  SigningKey SigningKey::random() {
    C_SigningKey *raw_key = signing_key_random();
    if (raw_key == nullptr) {
      throw "Failed to generate random signing key";
    }
    return SigningKey(raw_key);
  }

  SigningKey::~SigningKey() { signing_key_destroy(raw); }

  SignedToken SigningKey::sign(BlindedToken *tok) {
    C_SignedToken *raw_signed = signing_key_sign(raw, tok->raw);
    if (raw_signed == nullptr) {
      throw "Failed to sign, are inputs valid?";
    }

    return SignedToken(raw_signed);
  }

  UnblindedToken SigningKey::rederive_unblinded_token(TokenPreimage *t) {
    C_UnblindedToken *raw_unblinded = signing_key_rederive_unblinded_token(raw, t->raw);
    if (raw_unblinded == nullptr) {
      throw "Failed to rederive, are inputs valid?";
    }

    return UnblindedToken(raw_unblinded);
  }

  SigningKey SigningKey::decode_base64(const std::string encoded) { 
    C_SigningKey *raw_key = signing_key_decode_base64(encoded.c_str());
    if (raw_key == nullptr) {
      throw "Failed to decode";
    }
    return SigningKey(raw_key);
  }

  std::string SigningKey::encode_base64() { 
    char* tmp = signing_key_encode_base64(raw);
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}
