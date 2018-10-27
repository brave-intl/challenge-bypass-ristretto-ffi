#include <iostream>
#include "wrapper.hpp"

using namespace std;
using namespace challenge_bypass_ristretto;

int main() {
  // Server setup

  SigningKey sKey = SigningKey::random();
  PublicKey pKey = sKey.public_key();

  // Signing

  // client prepares a random token and blinding scalar
  Token tok = Token::random();
  // client stores the original token
  std::string base64_tok = tok.encode_base64();
  cout<<"[CLIENT] base64_tok: "<<base64_tok<<"\n";

  // client blinds the token
  BlindedToken blinded_tok = tok.blind();
  // and sends it to the server
  std::string base64_blinded_tok = blinded_tok.encode_base64();
  cout<<"[CLIENT] base64_blinded_tok: "<<base64_blinded_tok<<"\n";

  // server decodes it
  BlindedToken server_blinded_tok = BlindedToken::decode_base64(base64_blinded_tok);
  // server signs the blinded token 
  SignedToken server_signed_tok = sKey.sign(server_blinded_tok);
  // server signs a dleq proof
  DLEQProof server_proof = DLEQProof(server_blinded_tok, server_signed_tok, sKey);
  // for cases where multiple points are signed, a batch proof can be returned
  std::vector<BlindedToken> server_blinded_toks = {server_blinded_tok};
  std::vector<SignedToken> server_signed_toks = {server_signed_tok};
  BatchDLEQProof server_batch_proof = BatchDLEQProof(server_blinded_toks, server_signed_toks, sKey);
  // and returns the blinded token and dleq proof to the client
  std::string base64_signed_tok = server_signed_tok.encode_base64();
  cout<<"[SERVER] base64_signed_tok: "<<base64_signed_tok<<"\n";

  std::string base64_proof = server_proof.encode_base64();
  cout<<"[SERVER] base64_proof: "<<base64_proof<<"\n";
  std::string base64_batch_proof = server_batch_proof.encode_base64();
  cout<<"[SERVER] base64_batch_proof: "<<base64_batch_proof<<"\n";

  // client decodes them
  SignedToken signed_tok = SignedToken::decode_base64(base64_signed_tok);
  DLEQProof proof = DLEQProof::decode_base64(base64_proof);
  BatchDLEQProof batch_proof = BatchDLEQProof::decode_base64(base64_batch_proof);
  // client verifies the dleq proof using known public key info
  if (!proof.verify(blinded_tok, signed_tok, pKey)) {
    cerr<<"ERROR: proof did not verify\n";
    return 1;
  }
  // the example batch proof should check out too
  std::vector<BlindedToken> blinded_toks = {blinded_tok};
  std::vector<SignedToken> signed_toks = {signed_tok};
  if (!batch_proof.verify(blinded_toks, signed_toks, pKey)) {
    cerr<<"ERROR: batch proof did not verify\n";
    return 1;
  }

  // client restores the stored token
  Token restored_tok = Token::decode_base64(base64_tok);
  // client uses the blinding scalar to unblind the returned signed token
  UnblindedToken client_unblinded_tok = restored_tok.unblind(signed_tok);
  // client stores the unblinded token
  std::string base64_unblinded_tok = client_unblinded_tok.encode_base64();
  cout<<"[CLIENT] base64_unblinded_tok: "<<base64_unblinded_tok<<"\n";

  // Redemption 

  // client later restore the unblinded token in order to redeem
  UnblindedToken restored_unblinded_tok = UnblindedToken::decode_base64(base64_unblinded_tok);
  // client derives the shared key from the unblinded token
  VerificationKey client_vKey = restored_unblinded_tok.derive_verification_key();
  // client signs a message using the shared key
  std::string message = "test message";
  VerificationSignature client_sig = client_vKey.sign(message);
  // client sends the token preimage, signature and message to the server
  std::string base64_token_preimage = client_unblinded_tok.preimage().encode_base64();
  std::string base64_signature = client_sig.encode_base64();

  // server decodes the token preimage and signature
  TokenPreimage server_preimage = TokenPreimage::decode_base64(base64_token_preimage);
  VerificationSignature server_sig = VerificationSignature::decode_base64(base64_signature);
  // server derives the unblinded token using it's key and the clients token preimage
  UnblindedToken server_unblinded_tok = sKey.rederive_unblinded_token(server_preimage);
  // server derives the shared key from the unblinded token
  VerificationKey server_vKey = server_unblinded_tok.derive_verification_key();

  // The server verifies the client signature
  if (server_vKey.verify(server_sig, message)) {
      cout<<"sigs equal\n";
    }

  if (server_vKey.verify(server_sig, "foobar")) {
    cerr<<"ERROR: wrong sigs equal\n";
    return 1;
  }

  SigningKey sKey2 = SigningKey::random();
  UnblindedToken server_unblinded_tok2 = sKey2.rederive_unblinded_token(server_preimage);
  VerificationKey server_vKey2 = server_unblinded_tok2.derive_verification_key();

  if (server_vKey2.verify(server_sig, message)) {
    cerr<<"ERROR: wrong sigs equal\n";
    return 1;
  }

  return 0;
}
