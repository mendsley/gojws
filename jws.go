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
	ALG_HS384 = Algorithm("HS384")
	ALG_HS512 = Algorithm("HS512")
	ALG_RS256 = Algorithm("RS256")
	ALG_RS384 = Algorithm("RS384")
	ALG_RS512 = Algorithm("RS512")
	ALG_ES256 = Algorithm("ES256")
	ALG_ES384 = Algorithm("ES384")
	ALG_ES512 = Algorithm("ES512")
	ALG_PS256 = Algorithm("PS256")
	ALG_PS384 = Algorithm("PS384")
	ALG_PS512 = Algorithm("PS512")
)

// Public key to use for "none" algorithm. This type effectively
// works as a flag allowing no signature verification if none
// is provided in the JWS
type NoneKeyType int

const NoneKey = NoneKeyType(0)

// Allows caller access to the JWS header while selecting an
// appropriate public key.
type KeyProvider interface {
	GetJWSKey(h Header) (crypto.PublicKey, error)
}

// convert a single key into a provider
func ProviderFromKey(key crypto.PublicKey) KeyProvider {
	return singleKey{key: key}
}

type singleKey struct {
	key crypto.PublicKey
}

func (sk singleKey) GetJWSKey(h Header) (crypto.PublicKey, error) {
	return sk.key, nil
}

// JWS header
type Header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ,omitempty"`
	Cty string    `json:"typ,omitempty"`
	Jku string    `json:"jku,omitempty"`
	Jwk string    `json:"jwk,omitempty"`
	X5u string    `json:"x5u,omitempty"`
	X5t string    `json:"x5t,omitempty"`
	X5c string    `json:"x5c,omitempty"`
	Kid string    `json:"kid,omitempty"`
}

// Verify the authenticity of a JWS signature
func VerifyAndDecodeWithHeader(jws string, kp KeyProvider) (header Header, payload []byte, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		err = errors.New("Malformed JWS")
		return
	}

	// decode the JWS header
	data, err := safeDecode(parts[0])
	if err != nil {
		err = fmt.Errorf("Malformed JWS header: %v", err)
		return
	}
	err = json.Unmarshal(data, &header)
	if err != nil {
		err = fmt.Errorf("Failed to decode header: %v", err)
		return
	}

	// acquire the public key
	key, err := kp.GetJWSKey(header)
	if err != nil {
		err = fmt.Errorf("Failed to acquire public key: %v", err)
		return
	}

	// validate the signature
	signature, err := safeDecode(parts[2])
	if err != nil {
		err = fmt.Errorf("Malformed JWS signature: %v", err)
		return
	}

	switch header.Alg {
	case ALG_NONE:
		// only allow plaintext if the caller explicitly passed in the
		// "none" public key
		if key != NoneKey {
			err = errors.New("Refusing to validate plaintext JWS")
			return
		}

	case ALG_HS256, ALG_HS384, ALG_HS512:
		symmetricKey, ok := key.([]byte)
		if !ok {
			err = fmt.Errorf("Expected symmetric ([]byte) key. Got %T", key)
			return
		}

		var hfunc func() hash.Hash
		if header.Alg == ALG_HS256 {
			hfunc = sha256.New
		} else if header.Alg == ALG_HS384 {
			hfunc = sha512.New384
		} else if header.Alg == ALG_HS512 {
			hfunc = sha512.New
		} else {
			panic("Algorithm logic error with " + header.Alg)
		}

		hm := hmac.New(hfunc, symmetricKey)
		io.WriteString(hm, parts[0])
		io.WriteString(hm, ".")
		io.WriteString(hm, parts[1])

		expectedSignature := hm.Sum(nil)
		if !hmac.Equal(expectedSignature, signature) {
			err = errors.New("Signature verification failed")
			return
		}

	case ALG_RS256, ALG_RS384, ALG_RS512:
		pubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			privKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("Expected RSA key. Got %T", key)
				return
			}
			pubKey = &privKey.PublicKey
		}

		var htype crypto.Hash
		var hs hash.Hash
		if header.Alg == ALG_RS256 {
			hs = sha256.New()
			htype = crypto.SHA256
		} else if header.Alg == ALG_RS384 {
			hs = sha512.New384()
			htype = crypto.SHA384
		} else if header.Alg == ALG_RS512 {
			hs = sha512.New()
			htype = crypto.SHA512
		} else {
			panic("Algorithm logic error with " + header.Alg)
		}

		// generate hashed input
		io.WriteString(hs, parts[0])
		io.WriteString(hs, ".")
		io.WriteString(hs, parts[1])

		err = rsa.VerifyPKCS1v15(pubKey, htype, hs.Sum(nil), signature)
		if err != nil {
			err = errors.New("Signature verification failed")
			return
		}

	case ALG_ES256, ALG_ES384, ALG_ES512:
		pubKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			privKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("Expected ECDSA key. Got %T", key)
				return
			}

			pubKey = &privKey.PublicKey
		}

		var hs hash.Hash
		var rSize, sSize int
		if header.Alg == ALG_ES256 {
			rSize, sSize = 32, 32
			hs = sha256.New()
		} else if header.Alg == ALG_ES384 {
			rSize, sSize = 48, 48
			hs = sha512.New384()
		} else if header.Alg == ALG_ES512 {
			rSize, sSize = 66, 66
			hs = sha512.New()
		} else {
			panic("Alorithm logic error with " + header.Alg)
		}

		// split signature into R and S
		if len(signature) != rSize+sSize {
			err = errors.New("Signature verification failed")
			return
		}

		r, s := new(big.Int), new(big.Int)
		r.SetBytes(signature[:rSize])
		s.SetBytes(signature[rSize:])

		// generate hashed input
		io.WriteString(hs, parts[0])
		io.WriteString(hs, ".")
		io.WriteString(hs, parts[1])

		if !ecdsa.Verify(pubKey, hs.Sum(nil), r, s) {
			err = errors.New("Signature verification failed")
			return
		}

	case ALG_PS256, ALG_PS384, ALG_PS512:
		pubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			privKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("Expected RSA key. Got %T", key)
				return
			}

			pubKey = &privKey.PublicKey
		}

		var hs hash.Hash
		var htype crypto.Hash
		if header.Alg == ALG_PS256 {
			hs = sha256.New()
			htype = crypto.SHA256
		} else if header.Alg == ALG_PS384 {
			hs = sha512.New384()
			htype = crypto.SHA384
		} else if header.Alg == ALG_PS512 {
			hs = sha512.New()
			htype = crypto.SHA512
		} else {
			panic("Algorithm logic error with " + header.Alg)
		}

		// generate hashed input
		io.WriteString(hs, parts[0])
		io.WriteString(hs, ".")
		io.WriteString(hs, parts[1])

		err = rsa.VerifyPSS(pubKey, htype, hs.Sum(nil), signature, nil)
		if err != nil {
			err = errors.New("Signature verification failed")
			return
		}

	default:
		err = fmt.Errorf("Unknown signature algorithm: %s", header.Alg)
		return
	}

	// decode the payload
	payload, err = safeDecode(parts[1])
	if err != nil {
		err = fmt.Errorf("Malformed JWS payload: %v", err)
		return
	}
	return
}

func VerifyAndDecode(jws string, kp KeyProvider) (payload []byte, err error) {
	_, payload, err = VerifyAndDecodeWithHeader(jws, kp)
	return
}
