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
	"testing"
)

// Example JWS using RSASSA-PKCS-V1_5 using SHA-512
func TestVerify_RSASSA_PKCSV1_5_SHA512(t *testing.T) {
	const jws = `eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.RKJjn-vNsR-5iereV2pMyizIJZQHcjswduJory8PsJIG2UQFn7LZ8dnBbaA_CEP9a0Tb-zjo8DHmhhwUmYSLSxTipCjblmYvSw_8beJgEN_oP5wQODTyMu1u4vfAzgwLzqHvfBrI10mONNIWyyiEJQ87QuT7BcDn-n0Jyaw-gFltnpsiMxa4OZihV6SwECpokLaY9dvuJo3bzRvAAoejZXvkYPhaVo2mL2OW03mDjX0Pt_GZ4XLgXWJo7VgwpRUMKppZSWbqNtI9cQZV9a-oT22J_jc9leUXqGzQ8XsMYsIzy4m3AMe2LJqqQd9rzdw89uGUTxq3jBDf8YD-IkSfIg`
	const key = `{"kty":"RSA","n":"4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1_3Hc3cuUJwX_otNefr_Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI-pFtjjLBXD_zJmuL3Afg91J9p79-Dm-43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s_xHXgASl-hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF-hCdl_syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQ","e":"AQAB","d":"XaxT_DG8dvACFASmddUwxw7S2G06h3HMHPckzbFOGFadUODEI-QCFarZfQ1Kbmf0FjlqPDLFgfqF5NynqVqC3Fow42I1oTZbtOrHMzDr3q-GdjIv6QfZ736jASgq5xfPhBhq2qwkhA9va8zSH4N8UCBS82Bg1nZv00Gwuf2gEiYN9i54fKqlEZN1fm6sRW2ZDPTb3NoL6MVzsEpjqoFFJPAXCdWAT5N3xSB2s7clD_QjCT-WSmGeGWz8Fi900Lk7ygSmmjM1WYxXyObrUr5qA6HUoPyTLrSJAWOjdV0WlSMj5bT6xiJikNvj5n04s5Mr_knYQEAaKb2yLJ2AeynH5Q"}`

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

// Example JWS using RSASSA-PSS using SHA-256 and MGF1 with SHA-256
func TestVerify_RSASSA_PSS_SHA256(t *testing.T) {
	const jws = `eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.stBiNAnU_9b3Ug5_0xSWFPcqmY4vPwVbJ2Sy1La2WQeTtUQQIUoEJdUMZl5SqBRFiKDHS1UdrxrcPhNa6e_pTKcT8Goi3ADE9K8ffhlBSSAALSA0sPFW6syYH2IXsoR7j2vC77MG82C5Ub45UhqRt3tDELcEJ0QUKOjkM-9JY1TMcel7cdiYLqq3pbYhdzsBjUPtXrB9PpNdpkdXLHrF4QzDjgorg7_MwVmLCQ4QkYmbCgR2R7WUzws4TgaXWcj_oVG01ppagDORwqYFC9Oe87hMws_Sembt0i66wUqiZ7JHSlOnLAUjvLf61sEWY_zO-2t2HHkdNh5JxyzOc_9yOA`
	const key = `{"kty":"RSA","n":"4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1_3Hc3cuUJwX_otNefr_Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI-pFtjjLBXD_zJmuL3Afg91J9p79-Dm-43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s_xHXgASl-hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF-hCdl_syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQ","e":"AQAB","d":"XaxT_DG8dvACFASmddUwxw7S2G06h3HMHPckzbFOGFadUODEI-QCFarZfQ1Kbmf0FjlqPDLFgfqF5NynqVqC3Fow42I1oTZbtOrHMzDr3q-GdjIv6QfZ736jASgq5xfPhBhq2qwkhA9va8zSH4N8UCBS82Bg1nZv00Gwuf2gEiYN9i54fKqlEZN1fm6sRW2ZDPTb3NoL6MVzsEpjqoFFJPAXCdWAT5N3xSB2s7clD_QjCT-WSmGeGWz8Fi900Lk7ygSmmjM1WYxXyObrUr5qA6HUoPyTLrSJAWOjdV0WlSMj5bT6xiJikNvj5n04s5Mr_knYQEAaKb2yLJ2AeynH5Q"}`

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

// Example JWS using RSASSA-PSS using SHA-512 and MGF1 with SHA-512
func TestVerify_RSASSA_PSS_SHA512(t *testing.T) {
	const jws = `eyJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.nRbomc-CGIeZ-fxZNUagpie3U0r4dsszfAg7aebTJ3kejaid2P57xKazs1Z3gCpl1QYX29f_aRyFcWIkzZTd_q2_I990u3kxZ2eQuhR2kJFOT4uNhfIF34lfnuCtUHa-iSnifLEv4ueG5zQOwy7sYrnxtCJ3PaF1e5NCCFm9fn-acQVkkENHftphyyI-Tk6kDPouHnw2BiWtsYEcpWdSZPWKM_4bCAC_2Fj6wA2BOCvXVo7FfXzKNQZBJ6s1nknxchK4n0Zz3qTIR-F_To-Isz9CMa6z80ts326mZSqm6P4ZgTaqLK5Qcj-6wpD9r6FLYb7V4eo0KsDjcHpAyV47Mw`
	const key = `{"kty":"RSA","n":"4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1_3Hc3cuUJwX_otNefr_Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI-pFtjjLBXD_zJmuL3Afg91J9p79-Dm-43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s_xHXgASl-hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF-hCdl_syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQ","e":"AQAB","d":"XaxT_DG8dvACFASmddUwxw7S2G06h3HMHPckzbFOGFadUODEI-QCFarZfQ1Kbmf0FjlqPDLFgfqF5NynqVqC3Fow42I1oTZbtOrHMzDr3q-GdjIv6QfZ736jASgq5xfPhBhq2qwkhA9va8zSH4N8UCBS82Bg1nZv00Gwuf2gEiYN9i54fKqlEZN1fm6sRW2ZDPTb3NoL6MVzsEpjqoFFJPAXCdWAT5N3xSB2s7clD_QjCT-WSmGeGWz8Fi900Lk7ygSmmjM1WYxXyObrUr5qA6HUoPyTLrSJAWOjdV0WlSMj5bT6xiJikNvj5n04s5Mr_knYQEAaKb2yLJ2AeynH5Q"}`

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
