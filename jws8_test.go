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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"
)

// A.1 - JWS using HMAC SHA-256
func TestVerify8_HMAC_SHA26(t *testing.T) {
	const jws = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	key := []byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
		143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
		46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
		98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
		208, 128, 163}

	err := Verify(jws, key)
	if err != nil {
		t.Fatal("Verify: ", err)
	}
}

// A.2 - JWS using RSA SHA-256
func TestVerify8_RSA_SHA256(t *testing.T) {
	const jws = `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`

	key := &rsa.PublicKey{
		E: 65537,
		N: &big.Int{},
	}
	key.N.SetBytes([]byte{161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141,
		45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240,
		36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139,
		217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230,
		124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154,
		220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25,
		184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119,
		105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98,
		148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189,
		210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1,
		179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109,
		39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185,
		207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94,
		248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100,
		193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235,
		156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131,
		102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31,
		100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182,
		134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154,
		139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154,
		24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207,
		117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158,
		33, 224, 84, 86, 202, 229, 233, 161})

	err := Verify(jws, key)
	if err != nil {
		t.Fatal("Verify: ", err)
	}
}

// A.3 - JWS using ECDSA P-256 SHA-256
func TestVerify8_ECDSA_P256_SHA256(t *testing.T) {
	const jws = `eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q`

	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &big.Int{},
		Y:     &big.Int{},
	}
	key.X.SetBytes([]byte{127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203,
		238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239,
		19, 186, 207, 110, 60, 123, 209, 84, 69})
	key.Y.SetBytes([]byte{199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223,
		237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11,
		36, 173, 138, 70, 35, 40, 133, 136, 229, 173})

	err := Verify(jws, key)
	if err != nil {
		t.Fatal("Verify: ", err)
	}
}

// A.4 - JWS using ECDSA P-521 SHA-512
func TestVerify8_ECDSA_P521_SHA512(t *testing.T) {
	const jws = `eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn`

	key := &ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     &big.Int{},
		Y:     &big.Int{},
	}
	key.X.SetBytes([]byte{1, 233, 41, 5, 15, 18, 79, 198, 188, 85, 199, 213,
		57, 51, 101, 223, 157, 239, 74, 176, 194, 44, 178,
		87, 152, 249, 52, 235, 4, 227, 198, 186, 227, 112,
		26, 87, 167, 145, 14, 157, 129, 191, 54, 49, 89, 232,
		235, 203, 21, 93, 99, 73, 244, 189, 182, 204, 248,
		169, 76, 92, 89, 199, 170, 193, 1, 164})
	key.Y.SetBytes([]byte{0, 52, 166, 68, 14, 55, 103, 80, 210, 55, 31, 209,
		189, 194, 200, 243, 183, 29, 47, 78, 229, 234, 52,
		50, 200, 21, 204, 163, 21, 96, 254, 93, 147, 135,
		236, 119, 75, 85, 131, 134, 48, 229, 203, 191, 90,
		140, 190, 10, 145, 221, 0, 100, 198, 153, 154, 31,
		110, 110, 103, 250, 221, 237, 228, 200, 200, 246})

	err := Verify(jws, key)
	if err != nil {
		t.Fatal("Verify: ", err)
	}
}

// A.5 - Example Plaintext JWS
func TestVerify8_Plaintext(t *testing.T) {
	const jws = `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

	err := Verify(jws, NoneKey)
	if err != nil {
		t.Fatal("Verify: ", err)
	}
}
