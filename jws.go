// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package gojws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
)

type Algorithm string

const (
	ALG_NONE  = Algorithm("none")
	ALG_HS256 = Algorithm("HS256")
	ALG_RS256 = Algorithm("RS256")
	ALG_ES256 = Algorithm("ES256")
	ALG_ES512 = Algorithm("ES512")
)

// Public key to use for "none" algorithm. This type effectively
// works as a flag allowing no signature verification if none
// is provided in the JWS
type NoneKeyType int

const NoneKey = NoneKeyType(0)

// Verify the authenticity of a JWS signature
func Verify(jws string, key crypto.PublicKey) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("Malformed JWS")
	}

	// decode the JWS header
	var header struct {
		Alg Algorithm `json:"alg"`
	}
	data, err := safeDecode(parts[0])
	if err != nil {
		return fmt.Errorf("Malformed JWS header: %v", err)
	}
	err = json.Unmarshal(data, &header)
	if err != nil {
		return fmt.Errorf("Failed to decode header: %v", err)
	}

	// validate the signature
	signature, err := safeDecode(parts[2])
	if err != nil {
		return fmt.Errorf("Malformed JWS signature: %v", err)
	}

	switch header.Alg {
	case ALG_NONE:
		// only allow plaintext if the caller explicitly passed in the
		// "none" public key
		if key != NoneKey {
			return errors.New("Refusing to validate plaintext JWS")
		}

	case ALG_HS256:
		symmetricKey, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("Expected symmetric ([]byte) key. Got %T", key)
		}

		hm := hmac.New(sha256.New, symmetricKey)
		io.WriteString(hm, parts[0])
		io.WriteString(hm, ".")
		io.WriteString(hm, parts[1])

		expectedSignature := hm.Sum(nil)
		if !hmac.Equal(expectedSignature, signature) {
			return fmt.Errorf("Signature verification failed")
		}

	case ALG_RS256:
		pubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			privKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("Expected RSA key. Got %T", key)
			}
			pubKey = &privKey.PublicKey
		}

		// generate hashed input
		hs := sha256.New()
		io.WriteString(hs, parts[0])
		io.WriteString(hs, ".")
		io.WriteString(hs, parts[1])

		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hs.Sum(nil), signature)
		if err != nil {
			return fmt.Errorf("Signature verification failed")
		}

	case ALG_ES256, ALG_ES512:
		pubKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			privKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("Expected ECDSA key. Got %T", key)
			}

			pubKey = &privKey.PublicKey
		}

		var hs hash.Hash
		var rSize, sSize int
		if header.Alg == ALG_ES256 {
			rSize, sSize = 32, 32
			hs = sha256.New()
		} else if header.Alg == ALG_ES512 {
			rSize, sSize = 66, 66
			hs = sha512.New()
		} else {
			panic("Alorithm logic error with " + header.Alg)
		}

		// split signature into R and S
		if len(signature) != rSize+sSize {
			return fmt.Errorf("Signature verification failed")
		}

		r, s := new(big.Int), new(big.Int)
		r.SetBytes(signature[:rSize])
		s.SetBytes(signature[rSize:])

		// generate hashed input
		io.WriteString(hs, parts[0])
		io.WriteString(hs, ".")
		io.WriteString(hs, parts[1])

		if !ecdsa.Verify(pubKey, hs.Sum(nil), r, s) {
			return fmt.Errorf("Signature verification failed")
		}

	default:
		return fmt.Errorf("Unknown signature algorithm: %s", header.Alg)
	}

	return nil
}
