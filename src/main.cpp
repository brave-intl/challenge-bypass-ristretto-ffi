#include <iostream>
#include "wrapper.hpp"

using namespace std;

int main() {
  // Server setup

  SigningKey sKey = SigningKey();

  // Signing

  // client prepares a random token and blinding scalar
  Token tok = Token();
  // client blinds the token and sends it to the server
  BlindedToken blinded_tok = tok.blind();

  // server signs the blinded token and returns it to the client
  SignedToken signed_tok = sKey.sign(blinded_tok);

  // client uses the blinding scalar to unblind the returned signed token
  UnblindedToken client_unblinded_tok = tok.unblind(signed_tok);

  // Redemption 

  // client derives the shared key from the unblinded token
  VerificationKey client_vKey = client_unblinded_tok.derive_verification_key();
  // client signs a message using the shared key
  VerificationSignature client_sig = client_vKey.sign("test message");

  TokenPreimage preimage = client_unblinded_tok.preimage();
  // client sends the token preimage, signature and message to the server

  // server derives the unblinded token using it's key and the clients token preimage
  UnblindedToken server_unblinded_tok = sKey.rederive_unblinded_token(preimage);
  // server derives the shared key from the unblinded token
  VerificationKey server_vKey = server_unblinded_tok.derive_verification_key();
  // server signs the same message using the shared key
  VerificationSignature server_sig = server_vKey.sign("test message");

  // The server compares the client signature to it's own
  if (client_sig.equals(server_sig)) {
      cout<<"sigs equal\n";
    }

  VerificationSignature server_sig_wrong1 = server_vKey.sign("message");

  if (client_sig.equals(server_sig_wrong1)) {
    cout<<"ERROR: wrong sigs equal\n";
  }

  SigningKey sKey2 = SigningKey();
  UnblindedToken server_unblinded_tok2 = sKey2.rederive_unblinded_token(preimage);
  VerificationKey server_vKey2 = server_unblinded_tok2.derive_verification_key();
  VerificationSignature server_sig_wrong2 = server_vKey2.sign("test message");

  if (client_sig.equals(server_sig_wrong2)) {
    cout<<"ERROR: wrong sigs equal\n";
  }

  return 0;
}
