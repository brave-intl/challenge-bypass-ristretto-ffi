#ifndef _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP
#define _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP


#include<string>
#include<memory>
#include<vector>

extern "C" {
#include "lib.h"
}

namespace challenge_bypass_ristretto {
  class TokenException : std::exception {
  public:
    TokenException(const std::string& msg) : msg(msg){};
    static TokenException last_error(std::string msg);
    const char * what () const throw () {
        return msg.c_str();
     }

  private:
    std::string msg;
  };

  class TokenPreimage {
    friend class SigningKey;

    public:
      TokenPreimage(std::shared_ptr<C_TokenPreimage> raw) : raw(raw){}
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
      BlindedToken(std::shared_ptr<C_BlindedToken> raw) : raw(raw){}
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
      SignedToken(std::shared_ptr<C_SignedToken> raw) : raw(raw){}
      static SignedToken decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_SignedToken> raw;
  };

  class VerificationSignature {
    friend class VerificationKey;

    public:
      VerificationSignature(std::shared_ptr<C_VerificationSignature> raw) : raw(raw){}
      static VerificationSignature decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_VerificationSignature> raw;
  };

  class VerificationKey {
    public:
      VerificationKey(std::shared_ptr<C_VerificationKey> raw) : raw(raw){}
      VerificationSignature sign(const std::string);
      bool verify(VerificationSignature, const std::string);

    private:
      std::shared_ptr<C_VerificationKey> raw;
  };

  class UnblindedToken {
    public:
      UnblindedToken(std::shared_ptr<C_UnblindedToken> raw) : raw(raw){}
      VerificationKey derive_verification_key();
      TokenPreimage preimage();
      static UnblindedToken decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_UnblindedToken> raw;
  };

  class Token {
    public:
      Token(std::shared_ptr<C_Token> raw) : raw(raw){}
      static Token random();
      BlindedToken blind();
      UnblindedToken unblind(SignedToken);
      static Token decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_Token> raw;
  };

  class PublicKey {
    friend class DLEQProof;
    friend class BatchDLEQProof;

    public:
      PublicKey(std::shared_ptr<C_PublicKey> raw) : raw(raw){}
      static PublicKey decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_PublicKey> raw;
  };

  class SigningKey {
    friend class DLEQProof;
    friend class BatchDLEQProof;

    public:
      SigningKey(std::shared_ptr<C_SigningKey> raw) : raw(raw){}
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
      DLEQProof(std::shared_ptr<C_DLEQProof> raw) : raw(raw){}
      DLEQProof(BlindedToken, SignedToken, SigningKey);
      bool verify(BlindedToken, SignedToken, PublicKey);
      static DLEQProof decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_DLEQProof> raw;
  };

  class BatchDLEQProof {
    public:
      BatchDLEQProof(std::shared_ptr<C_BatchDLEQProof> raw) : raw(raw){}
      BatchDLEQProof(std::vector<BlindedToken>, std::vector<SignedToken>, SigningKey);
      bool verify(std::vector<BlindedToken>, std::vector<SignedToken>, PublicKey);
      static BatchDLEQProof decode_base64(const std::string);
      std::string encode_base64();

    private:
      std::shared_ptr<C_BatchDLEQProof> raw;
  };
}

#endif /* _CHALLENGE_BYPASS_RISTRETTO_WRAPPER_HPP */
