package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
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
	blindedToken := token.Blind()

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
	result, err := proof.Verify(blindedToken, signedToken, pKey)
	if err != nil {
		log.Fatalln(err)
	}
	if !result {
		log.Fatalln("Proof should have verified")
	}

	// client uses the blinding scalar to unblind the returned signed token
	clientUnblindedToken, err := token.Unblind(signedToken)
	if err != nil {
		log.Fatalln(err)
	}

	// Redemption

	// client derives the shared key from the unblinded token
	clientvKey := clientUnblindedToken.DeriveVerificationKey()

	// client signs a message using the shared key
	clientSig, err := clientvKey.Sign("test message")
	if err != nil {
		log.Fatalln(err)
	}
	preimage := clientUnblindedToken.Preimage()
	// client sends the token preimage, signature and message to the server

	// server derives the unblinded token using it's key and the clients token preimage
	serverUnblindedToken := sKey.RederiveUnblindedToken(preimage)

	// server derives the shared key from the unblinded token
	servervKey := serverUnblindedToken.DeriveVerificationKey()

	// server signs the same message using the shared key and compares the client signature to it's own
	result, err = servervKey.Verify(clientSig, "test message")
	if err != nil {
		log.Fatalln(err)
	}
	if result {
		fmt.Println("sigs equal")
	}

	// server signs the wrong message using the shared key and compares the client signature to it's own
	result, err = servervKey.Verify(clientSig, "message")
	if err != nil {
		log.Fatalln(err)
	}
	if result {
		log.Fatalln("ERROR: sigs equal")
	}

	// force finalizers to run
	runtime.GC()
	time.Sleep(time.Second)
}
