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

	// Signing

	// client prepares a random token and blinding scalar
	token, err := crypto.RandomToken()
	if err != nil {
		log.Fatalln(err)
	}
	// client blinds the token and sends it to the server
	blinded_token, err := token.Blind()
	if err != nil {
		log.Fatalln(err)
	}

	type Request struct {
		BlindedToken *crypto.BlindedToken `json:"blinded_token"`
	}
	req := Request{BlindedToken: blinded_token}
	json_encoded, err := json.Marshal(req)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(json_encoded))

	encoded, err := blinded_token.MarshalText()
	if err != nil {
		log.Fatalln(err)
	}
	var server_blinded_token crypto.BlindedToken
	err = server_blinded_token.UnmarshalText(encoded)
	if err != nil {
		log.Fatalln(err)
	}

	// server signs the blinded token and returns it to the client
	signed_token, err := sKey.Sign(&server_blinded_token)
	if err != nil {
		log.Fatalln(err)
	}

	// client uses the blinding scalar to unblind the returned signed token
	client_unblinded_token, err := token.Unblind(signed_token)
	if err != nil {
		log.Fatalln(err)
	}

	// Redemption

	// client derives the shared key from the unblinded token
	client_vKey, err := client_unblinded_token.DeriveVerificationKey()
	if err != nil {
		log.Fatalln(err)
	}

	// client signs a message using the shared key
	client_sig, err := client_vKey.Sign("test message")
	if err != nil {
		log.Fatalln(err)
	}
	preimage, err := client_unblinded_token.Preimage()
	if err != nil {
		log.Fatalln(err)
	}
	// client sends the token preimage, signature and message to the server

	// server derives the unblinded token using it's key and the clients token preimage
	server_unblinded_token, err := sKey.RederiveUnblindedToken(preimage)
	if err != nil {
		log.Fatalln(err)
	}

	// server derives the shared key from the unblinded token
	server_vKey, err := server_unblinded_token.DeriveVerificationKey()
	if err != nil {
		log.Fatalln(err)
	}

	// server signs the same message using the shared key and compares the client signature to it's own
	if server_vKey.Verify(client_sig, "test message") {
		fmt.Println("sigs equal")
	}

	// server signs the wrong message using the shared key and compares the client signature to it's own
	if server_vKey.Verify(client_sig, "message") {
		log.Fatalln("ERROR: sigs equal")
	}

	// force finalizers to run
	runtime.GC()
	time.Sleep(time.Second)
}
