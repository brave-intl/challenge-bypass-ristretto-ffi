#include<string>

class TokenPreimage {
  public:
    TokenPreimage(void *raw) : raw(raw){}
    ~TokenPreimage();

    void *raw;
};

class BlindedToken {
  public:
    BlindedToken(void *raw) : raw(raw){}
    std::string encode();
    ~BlindedToken();

    void *raw;
};
BlindedToken decode_blinded_token(const std::string);

class SignedToken {
  public:
    SignedToken(void *raw) : raw(raw){}
    ~SignedToken();

    void *raw;
};

class VerificationSignature {
  public:
    VerificationSignature(void *raw) : raw(raw){}
    ~VerificationSignature();
    bool equals(VerificationSignature);

  private:
    void *raw;
};

class VerificationKey {
  public:
    VerificationKey(void *raw) : raw(raw){}
    ~VerificationKey();
    VerificationSignature sign(const std::string);

  private:
    void *raw;
};

class UnblindedToken {
  public:
    UnblindedToken(void *raw) : raw(raw){}
    ~UnblindedToken();
    VerificationKey derive_verification_key();
    TokenPreimage preimage();

    void *raw;
};

class Token {
  public:
    Token();
    ~Token();
    BlindedToken blind();
    UnblindedToken unblind(SignedToken);

  private:
    void *raw;
};

class SigningKey {
  public:
    SigningKey();
    ~SigningKey();
    SignedToken sign(BlindedToken);
    UnblindedToken rederive_unblinded_token(TokenPreimage);

  private:
    void *raw;
};
