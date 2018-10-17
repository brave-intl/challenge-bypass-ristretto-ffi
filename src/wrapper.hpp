#include<string>

extern "C" {
#include "lib.h"
}

namespace challenge_bypass_ristretto {
  class TokenPreimage {
    friend class SigningKey;

    public:
      TokenPreimage(C_TokenPreimage *raw) : raw(raw){}
      ~TokenPreimage();
      static TokenPreimage decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_TokenPreimage *raw;
  };

  class BlindedToken {
    friend class SigningKey;

    public:
      BlindedToken(C_BlindedToken *raw) : raw(raw){}
      ~BlindedToken();
      static BlindedToken decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_BlindedToken *raw;
  };

  class SignedToken {
    friend class Token;

    public:
      SignedToken(C_SignedToken *raw) : raw(raw){}
      ~SignedToken();
      static SignedToken decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_SignedToken *raw;
  };

  class VerificationSignature {
    friend class VerificationKey;

    public:
      VerificationSignature(C_VerificationSignature *raw) : raw(raw){}
      ~VerificationSignature();
      static VerificationSignature decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_VerificationSignature *raw;
  };

  class VerificationKey {
    public:
      VerificationKey(C_VerificationKey *raw) : raw(raw){}
      ~VerificationKey();
      VerificationSignature sign(const std::string);
      bool verify(VerificationSignature*, const std::string);

    private:
      C_VerificationKey *raw;
  };

  class UnblindedToken {
    public:
      UnblindedToken(C_UnblindedToken *raw) : raw(raw){}
      ~UnblindedToken();
      VerificationKey derive_verification_key();
      TokenPreimage preimage();
      static UnblindedToken decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_UnblindedToken *raw;
  };

  class Token {
    public:
      Token(C_Token *raw) : raw(raw){}
      static Token random();
      ~Token();
      BlindedToken blind();
      UnblindedToken unblind(SignedToken*);
      static Token decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_Token *raw;
  };

  class SigningKey {
    public:
      SigningKey(C_SigningKey *raw) : raw(raw){}
      ~SigningKey();
      static SigningKey random();
      SignedToken sign(BlindedToken*);
      UnblindedToken rederive_unblinded_token(TokenPreimage*);
      static SigningKey decode_base64(const std::string);
      std::string encode_base64();

    private:
      C_SigningKey *raw;
  };
}
