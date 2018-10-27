package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	crypto "github.com/evq/challenge-bypass-ristretto-ffi"
)

func main() {
	// Server setup
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		log.Fatalln(err)
	}
	pKey := sKey.PublicKey()

	// Signing

	// client prepares a random token and blinding scalar
	token, err := crypto.RandomToken()
	if err != nil {
		log.Fatalln(err)
	}
	// client blinds the token and sends it to the server
	blindedToken, err := token.Blind()
	if err != nil {
		log.Fatalln(err)
	}

	type Request struct {
		BlindedToken *crypto.BlindedToken `json:"blinded_token"`
	}
	req := Request{BlindedToken: blindedToken}
	jsonEncoded, err := json.Marshal(req)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(jsonEncoded))

	encoded, err := blindedToken.MarshalText()
	if err != nil {
		log.Fatalln(err)
	}
	var serverBlindedToken crypto.BlindedToken
	err = serverBlindedToken.UnmarshalText(encoded)
	if err != nil {
		log.Fatalln(err)
	}

	// server signs the blinded token
	signedToken, err := sKey.Sign(&serverBlindedToken)
	if err != nil {
		log.Fatalln(err)
	}

	// server creates a DLEQ proof and returns it and the signed token to the client
	proof, err := crypto.NewDLEQProof(&serverBlindedToken, signedToken, sKey)
	if err != nil {
		log.Fatalln(err)
	}

	// client verifies the DLEQ proof
	if !proof.Verify(blindedToken, signedToken, pKey) {
		log.Fatalln("Proof should have verified")
	}

	// client uses the blinding scalar to unblind the returned signed token
	clientUnblindedToken, err := token.Unblind(signedToken)
	if err != nil {
		log.Fatalln(err)
	}

	// Redemption

	// client derives the shared key from the unblinded token
	clientvKey, err := clientUnblindedToken.DeriveVerificationKey()
	if err != nil {
		log.Fatalln(err)
	}

	// client signs a message using the shared key
	clientSig, err := clientvKey.Sign("test message")
	if err != nil {
		log.Fatalln(err)
	}
	preimage, err := clientUnblindedToken.Preimage()
	if err != nil {
		log.Fatalln(err)
	}
	// client sends the token preimage, signature and message to the server

	// server derives the unblinded token using it's key and the clients token preimage
	serverUnblindedToken, err := sKey.RederiveUnblindedToken(preimage)
	if err != nil {
		log.Fatalln(err)
	}

	// server derives the shared key from the unblinded token
	servervKey, err := serverUnblindedToken.DeriveVerificationKey()
	if err != nil {
		log.Fatalln(err)
	}

	// server signs the same message using the shared key and compares the client signature to it's own
	if servervKey.Verify(clientSig, "test message") {
		fmt.Println("sigs equal")
	}

	// server signs the wrong message using the shared key and compares the client signature to it's own
	if servervKey.Verify(clientSig, "message") {
		log.Fatalln("ERROR: sigs equal")
	}

	// force finalizers to run
	runtime.GC()
	time.Sleep(time.Second)
}
