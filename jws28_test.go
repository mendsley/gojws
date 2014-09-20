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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

func keyFromJWK(jwk string) (crypto.PrivateKey, error) {
	var key struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		D   string `json:"d"`
		K   string `json:"k"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal key: %v", err)
	}

	switch key.Kty {
	case "RSA":
		if key.N == "" || key.E == "" || key.D == "" {
			return nil, errors.New("Malformed JWS RSA key")
		}

		// decode exponent
		data, err := safeDecode(key.E)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		if len(data) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(data):], data)
			data = ndata
		}

		privKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: &big.Int{},
				E: int(binary.BigEndian.Uint32(data[:])),
			},
			D: &big.Int{},
		}

		data, err = safeDecode(key.N)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		privKey.PublicKey.N.SetBytes(data)

		data, err = safeDecode(key.D)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		privKey.D.SetBytes(data)

		return privKey, nil

	case "oct":
		if key.K == "" {
			return nil, errors.New("Malformed JWS octect key")
		}

		data, err := safeDecode(key.K)
		if err != nil {
			return nil, errors.New("Malformed JWS octect key")
		}

		return data, nil

	case "EC":
		if key.Crv == "" || key.X == "" || key.Y == "" || key.D == "" {
			return nil, errors.New("Malformed JWS EC key")
		}

		var curve elliptic.Curve
		switch key.Crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("Unknown curve type: %s", key.Crv)
		}

		privKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     &big.Int{},
				Y:     &big.Int{},
			},
			D: &big.Int{},
		}

		data, err := safeDecode(key.X)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWS EC key")
		}
		privKey.PublicKey.X.SetBytes(data)

		data, err = safeDecode(key.Y)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWS EC key")
		}
		privKey.PublicKey.Y.SetBytes(data)

		data, err = safeDecode(key.D)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWS EC key")
		}
		privKey.D.SetBytes(data)

		return privKey, nil

	default:
		return nil, fmt.Errorf("Unknown JWS key type %s", key.Kty)
	}
}

// A.1 - Example JWS using HMAC SHA-256
func TestVerify28_HMAC_SHA256(t *testing.T) {
	const jws = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	const key = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

	pubKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecode(jws, ProviderFromKey(pubKey))
	if err != nil {
		t.Fatal("Verify: ", err)
	}

	if !bytes.Equal(data, []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}) {
		t.Fatalf("Unexpected payload: %v", data)
	}
}

// A.2 Example JWS using RSASSA-PKCS-v1_5 SHA-256
func TestVerify28_RSASSA_PKCS_V1_5_SHA256(t *testing.T) {
	const jws = `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
	const key = `{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB","d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"}`

	pubKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecode(jws, ProviderFromKey(pubKey))
	if err != nil {
		t.Fatal("Verify: ", err)
	}

	if !bytes.Equal(data, []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}) {
		t.Fatalf("Unexpected payload: %v", data)
	}
}

// A.3 Example JWS using ECDSA P-256 SHA-256
func TestVerify28_ECDSA_P256_SHA256(t *testing.T) {
	const jws = `eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q`
	const key = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`

	pubKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecode(jws, ProviderFromKey(pubKey))
	if err != nil {
		t.Fatal("Verify: ", err)
	}

	if !bytes.Equal(data, []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}) {
		t.Fatalf("Unexpected payload: %v", data)
	}
}

// A.4 Example JWS using ECDSA P-521 SHA-512
func TestVerify28_ECDSA_P521_SHA512(t *testing.T) {
	const jws = `eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn`
	const key = `{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2","d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}`

	pubKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecode(jws, ProviderFromKey(pubKey))
	if err != nil {
		t.Fatal("Verify: ", err)
	}

	if !bytes.Equal(data, []byte{80, 97, 121, 108, 111, 97, 100}) {
		t.Fatalf("Unexpected payload: %v", data)
	}
}

// A.5 - Example Plaintext JWS
func TestVerify28_NONE(t *testing.T) {
	const jws = `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

	data, err := VerifyAndDecode(jws, ProviderFromKey(NoneKey))
	if err != nil {
		t.Fatal("Verify: ", err)
	}

	if !bytes.Equal(data, []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}) {
		t.Fatalf("Unexpected payload: %v", data)
	}
}
