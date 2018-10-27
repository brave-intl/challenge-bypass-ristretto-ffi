#include "wrapper.hpp"

extern "C" {
#include "lib.h"
}

// class TokenPreimage
namespace challenge_bypass_ristretto {

  TokenPreimage TokenPreimage::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_TokenPreimage> raw_preimage(token_preimage_decode_base64(encoded.c_str()), token_preimage_destroy);
    if (raw_preimage == nullptr) {
      throw "Failed to decode";
    }
    return TokenPreimage(raw_preimage);
  }

  std::string TokenPreimage::encode_base64() { 
    char* tmp = token_preimage_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class Token
namespace challenge_bypass_ristretto {
  Token Token::random() {
    std::shared_ptr<C_Token> raw_token(token_random(), token_destroy);
    if (raw_token == nullptr) {
      throw "Failed to generate random token";
    }
    return Token(raw_token);
  }

  BlindedToken Token::blind() {
    std::shared_ptr<C_BlindedToken> raw_blinded(token_blind(raw.get()), blinded_token_destroy);
    if (raw_blinded == nullptr) {
      throw "Failed to blind, is token valid?";
    }

    return BlindedToken(raw_blinded);
  }

  UnblindedToken Token::unblind(SignedToken tok) {
    std::shared_ptr<C_UnblindedToken> raw_unblinded(token_unblind(raw.get(), tok.raw.get()), unblinded_token_destroy);
    if (raw_unblinded == nullptr) {
      throw "Failed to unblind, are inputs valid?";
    }

    return UnblindedToken(raw_unblinded);
  }

  Token Token::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_Token> raw_tok(token_decode_base64(encoded.c_str()), token_destroy);
    if (raw_tok == nullptr) {
      throw "Failed to decode";
    }
    return Token(raw_tok);
  }

  std::string Token::encode_base64() { 
    char* tmp = token_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class BlindedToken
namespace challenge_bypass_ristretto {
  BlindedToken BlindedToken::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_BlindedToken> raw_blinded(blinded_token_decode_base64(encoded.c_str()), blinded_token_destroy);
    if (raw_blinded == nullptr) {
      throw "Failed to decode";
    }
    return BlindedToken(raw_blinded);
  }

  std::string BlindedToken::encode_base64() { 
    char* tmp = blinded_token_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class SignedToken
namespace challenge_bypass_ristretto {
  SignedToken SignedToken::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_SignedToken> raw_signed(signed_token_decode_base64(encoded.c_str()), signed_token_destroy);
    if (raw_signed == nullptr) {
      throw "Failed to decode";
    }
    return SignedToken(raw_signed);
  }

  std::string SignedToken::encode_base64() { 
    char* tmp = signed_token_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class VerificationSignature
namespace challenge_bypass_ristretto {
  VerificationSignature VerificationSignature::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_VerificationSignature> raw_sig(verification_signature_decode_base64(encoded.c_str()), verification_signature_destroy);
    if (raw_sig == nullptr) {
      throw "Failed to decode";
    }
    return VerificationSignature(raw_sig);
  }

  std::string VerificationSignature::encode_base64() { 
    char* tmp = verification_signature_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class UnblindedToken
namespace challenge_bypass_ristretto {
  VerificationKey UnblindedToken::derive_verification_key() {
    std::shared_ptr<C_VerificationKey> raw_verification_key(unblinded_token_derive_verification_key_sha512(raw.get()), verification_key_destroy);
    if (raw_verification_key == nullptr) {
      throw "Failed to derive verification key, are inputs valid?";
    }

    return VerificationKey(raw_verification_key);
  }

  TokenPreimage UnblindedToken::preimage() {
    std::shared_ptr<C_TokenPreimage> raw_preimage(unblinded_token_preimage(raw.get()), token_preimage_destroy);
    if (raw_preimage == nullptr) {
      throw "Failed to get preimage, are inputs valid?";
    }

    return TokenPreimage(raw_preimage);
  }

  UnblindedToken UnblindedToken::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_UnblindedToken> raw_unblinded(unblinded_token_decode_base64(encoded.c_str()), unblinded_token_destroy);
    if (raw_unblinded == nullptr) {
      throw "Failed to decode";
    }
    return UnblindedToken(raw_unblinded);
  }

  std::string UnblindedToken::encode_base64() { 
    char* tmp = unblinded_token_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class VerificationKey
namespace challenge_bypass_ristretto {
  VerificationSignature VerificationKey::sign(const std::string message) {
    std::shared_ptr<C_VerificationSignature> raw_verification_signature(verification_key_sign_sha512(raw.get(), message.c_str()), verification_signature_destroy);
    if (raw_verification_signature == nullptr) {
      throw "Invalid message";
    }
    return VerificationSignature(raw_verification_signature);
  }

  bool VerificationKey::verify(VerificationSignature sig, const std::string message) {
    return verification_key_verify_sha512(raw.get(), sig.raw.get(), message.c_str());
  }
}

// class SigningKey
namespace challenge_bypass_ristretto {
  SigningKey SigningKey::random() {
    std::shared_ptr<C_SigningKey> raw_key(signing_key_random(), signing_key_destroy);
    if (raw_key == nullptr) {
      throw "Failed to generate random signing key";
    }
    return SigningKey(raw_key);
  }

  SignedToken SigningKey::sign(BlindedToken tok) {
    std::shared_ptr<C_SignedToken> raw_signed(signing_key_sign(raw.get(), tok.raw.get()), signed_token_destroy);
    if (raw_signed == nullptr) {
      throw "Failed to sign, are inputs valid?";
    }

    return SignedToken(raw_signed);
  }

  UnblindedToken SigningKey::rederive_unblinded_token(TokenPreimage t) {
    std::shared_ptr<C_UnblindedToken> raw_unblinded(signing_key_rederive_unblinded_token(raw.get(), t.raw.get()), unblinded_token_destroy);
    if (raw_unblinded == nullptr) {
      throw "Failed to rederive, are inputs valid?";
    }

    return UnblindedToken(raw_unblinded);
  }

  PublicKey SigningKey::public_key() {
    std::shared_ptr<C_PublicKey> raw_key(signing_key_get_public_key(raw.get()), public_key_destroy);
    if (raw_key == nullptr) {
      throw "Failed to get public key, are inputs valid?";
    }

    return PublicKey(raw_key);
  }

  SigningKey SigningKey::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_SigningKey> raw_key(signing_key_decode_base64(encoded.c_str()), signing_key_destroy);
    if (raw_key == nullptr) {
      throw "Failed to decode";
    }
    return SigningKey(raw_key);
  }

  std::string SigningKey::encode_base64() { 
    char* tmp = signing_key_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class PublicKey
namespace challenge_bypass_ristretto {
  PublicKey PublicKey::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_PublicKey> raw_key(public_key_decode_base64(encoded.c_str()), public_key_destroy);
    if (raw_key == nullptr) {
      throw "Failed to decode";
    }
    return PublicKey(raw_key);
  }

  std::string PublicKey::encode_base64() { 
    char* tmp = public_key_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class DLEQProof
namespace challenge_bypass_ristretto {
  DLEQProof::DLEQProof(BlindedToken blinded_token, SignedToken signed_token, SigningKey key) { 
    raw = std::shared_ptr<C_DLEQProof>(dleq_proof_new(blinded_token.raw.get(), signed_token.raw.get(), key.raw.get()), dleq_proof_destroy);
  }

  bool DLEQProof::verify(BlindedToken blinded_token, SignedToken signed_token, PublicKey key) { 
    return dleq_proof_verify(raw.get(), blinded_token.raw.get(), signed_token.raw.get(), key.raw.get());
  }

  DLEQProof DLEQProof::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_DLEQProof> raw_proof(dleq_proof_decode_base64(encoded.c_str()), dleq_proof_destroy);
    if (raw_proof == nullptr) {
      throw "Failed to decode";
    }
    return DLEQProof(raw_proof);
  }

  std::string DLEQProof::encode_base64() { 
    char* tmp = dleq_proof_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}

// class BatchDLEQProof
namespace challenge_bypass_ristretto {
  BatchDLEQProof::BatchDLEQProof(std::vector<BlindedToken> blinded_tokens, std::vector<SignedToken> signed_tokens, SigningKey key) { 
    if (blinded_tokens.size() != signed_tokens.size()) {
      throw "Blinded tokens and signed tokens must have the same length";
    }
    std::vector<C_BlindedToken*> raw_blinded_tokens;
    std::vector<C_SignedToken*> raw_signed_tokens;

    for (int i = 0; i < blinded_tokens.size(); i++) {
      raw_blinded_tokens.push_back(blinded_tokens[i].raw.get());
      raw_signed_tokens.push_back(signed_tokens[i].raw.get());
    }

    raw = std::shared_ptr<C_BatchDLEQProof>(batch_dleq_proof_new(raw_blinded_tokens.data(), raw_signed_tokens.data(), blinded_tokens.size(), key.raw.get()), batch_dleq_proof_destroy);
  }

  bool BatchDLEQProof::verify(std::vector<BlindedToken> blinded_tokens, std::vector<SignedToken> signed_tokens, PublicKey key) { 
    if (blinded_tokens.size() != signed_tokens.size()) {
      throw "Blinded tokens and signed tokens must have the same length";
    }
    std::vector<C_BlindedToken*> raw_blinded_tokens;
    std::vector<C_SignedToken*> raw_signed_tokens;

    for (int i = 0; i < blinded_tokens.size(); i++) {
      raw_blinded_tokens.push_back(blinded_tokens[i].raw.get());
      raw_signed_tokens.push_back(signed_tokens[i].raw.get());
    }

    return bool(batch_dleq_proof_verify(raw.get(), raw_blinded_tokens.data(), raw_signed_tokens.data(), blinded_tokens.size(), key.raw.get()));
  }

  BatchDLEQProof BatchDLEQProof::decode_base64(const std::string encoded) { 
    std::shared_ptr<C_BatchDLEQProof> raw_proof(batch_dleq_proof_decode_base64(encoded.c_str()), batch_dleq_proof_destroy);
    if (raw_proof == nullptr) {
      throw "Failed to decode";
    }
    return BatchDLEQProof(raw_proof);
  }

  std::string BatchDLEQProof::encode_base64() { 
    char* tmp = batch_dleq_proof_encode_base64(raw.get());
    std::string result = std::string(tmp);
    c_char_destroy(tmp);
    return result;
  }
}
