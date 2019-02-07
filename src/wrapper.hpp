#ifndef _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP
#define _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP

#include <memory>
#include <string>
#include <vector>

extern "C" {
#include "lib.h"
}

namespace challenge_bypass_ristretto {

class TokenException : std::exception {
 public:
  TokenException(const std::string& msg);
  ~TokenException() override;
  static TokenException last_error(std::string msg);
  const char* what() const noexcept override;
#ifdef NO_CXXEXCEPTIONS
  static const TokenException& none();
  static void set_last_exception(const TokenException& exception);
  bool is_empty() const;
#endif

 private:
  std::string msg_;
};

#ifdef NO_CXXEXCEPTIONS
bool exception_occurred();
const TokenException get_last_exception();
#endif

class TokenPreimage {
  friend class SigningKey;

 public:
  TokenPreimage(std::shared_ptr<C_TokenPreimage>);
  TokenPreimage(const TokenPreimage&);
  ~TokenPreimage();
  static TokenPreimage decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_TokenPreimage> raw;
};

class BlindedToken {
  friend class SigningKey;
  friend class DLEQProof;
  friend class BatchDLEQProof;

 public:
  BlindedToken(std::shared_ptr<C_BlindedToken>);
  BlindedToken(const BlindedToken&);
  ~BlindedToken();
  static BlindedToken decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_BlindedToken> raw;
};

class SignedToken {
  friend class Token;
  friend class DLEQProof;
  friend class BatchDLEQProof;

 public:
  SignedToken(std::shared_ptr<C_SignedToken>);
  SignedToken(const SignedToken&);
  ~SignedToken();
  static SignedToken decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_SignedToken> raw;
};

class VerificationSignature {
  friend class VerificationKey;

 public:
  VerificationSignature(std::shared_ptr<C_VerificationSignature>);
  VerificationSignature(const VerificationSignature&);
  ~VerificationSignature();
  static VerificationSignature decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_VerificationSignature> raw;
};

class VerificationKey {
 public:
  VerificationKey(std::shared_ptr<C_VerificationKey>);
  VerificationKey(const VerificationKey&);
  ~VerificationKey();
  VerificationSignature sign(const std::string);
  bool verify(VerificationSignature, const std::string);

 private:
  std::shared_ptr<C_VerificationKey> raw;
};

class UnblindedToken {
 public:
  UnblindedToken(std::shared_ptr<C_UnblindedToken>);
  UnblindedToken(const UnblindedToken&);
  ~UnblindedToken();
  VerificationKey derive_verification_key();
  TokenPreimage preimage();
  static UnblindedToken decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_UnblindedToken> raw;
};

class Token {
  friend class BatchDLEQProof;

 public:
  Token(std::shared_ptr<C_Token>);
  Token(const Token&);
  ~Token();
  static Token random();
  BlindedToken blind();
  static Token decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_Token> raw;
};

class PublicKey {
  friend class DLEQProof;
  friend class BatchDLEQProof;

 public:
  PublicKey(std::shared_ptr<C_PublicKey>);
  PublicKey(const PublicKey&);
  ~PublicKey();
  static PublicKey decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_PublicKey> raw;
};

class SigningKey {
  friend class DLEQProof;
  friend class BatchDLEQProof;

 public:
  SigningKey(std::shared_ptr<C_SigningKey>);
  SigningKey(const SigningKey&);
  ~SigningKey();
  static SigningKey random();
  SignedToken sign(BlindedToken);
  UnblindedToken rederive_unblinded_token(TokenPreimage);
  PublicKey public_key();
  static SigningKey decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_SigningKey> raw;
};

class DLEQProof {
 public:
  DLEQProof(std::shared_ptr<C_DLEQProof>);
  DLEQProof(const DLEQProof&);
  DLEQProof(BlindedToken, SignedToken, SigningKey);
  ~DLEQProof();
  bool verify(BlindedToken, SignedToken, PublicKey);
  static DLEQProof decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_DLEQProof> raw;
};

class BatchDLEQProof {
 public:
  BatchDLEQProof(std::shared_ptr<C_BatchDLEQProof>);
  BatchDLEQProof(const BatchDLEQProof&);
  BatchDLEQProof(std::vector<BlindedToken>,
                 std::vector<SignedToken>,
                 SigningKey);
  ~BatchDLEQProof();
  bool verify(std::vector<BlindedToken>, std::vector<SignedToken>, PublicKey);
  std::vector<UnblindedToken> verify_and_unblind(std::vector<Token>, std::vector<BlindedToken>, std::vector<SignedToken>, PublicKey);
  static BatchDLEQProof decode_base64(const std::string);
  std::string encode_base64();

 private:
  std::shared_ptr<C_BatchDLEQProof> raw;
};

}  // namespace challenge_bypass_ristretto

#endif /* _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP */
