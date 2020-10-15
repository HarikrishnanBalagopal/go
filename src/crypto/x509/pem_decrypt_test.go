// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDecrypt(t *testing.T) {
	for i, data := range testData {
		t.Logf("test %v. %v", i, data.kind)
		block, rest := pem.Decode(data.pemData)
		if len(rest) > 0 {
			t.Error("extra data")
		}
		der, err := DecryptPEMBlock(block, data.password)
		if err != nil {
			t.Error("decrypt failed: ", err)
			continue
		}
		if _, err := ParsePKCS1PrivateKey(der); err != nil {
			t.Error("invalid private key: ", err)
		}
		plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
		if err != nil {
			t.Fatal("cannot decode test DER data: ", err)
		}
		if !bytes.Equal(der, plainDER) {
			t.Error("data mismatch")
		}
	}
}

func TestDecryptPKCS8(t *testing.T) {
	block, rest := pem.Decode([]byte(pkcs8KeyWithPassword))
	if block == nil {
		t.Fatal("block is nil")
	}
	if len(rest) > 0 {
		t.Fatal("some extra bytes")
	}
	if !IsEncryptedPEMBlock(block) {
		t.Fatal("failed to detect that block is encrypted")
	}
	derBytes, err := DecryptPEMBlock(block, []byte(mypassword))
	if err != nil {
		t.Fatal("failed to decrypt the PKCS8 format encrypted private key. Error:", err)
	}
	decblk := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}
	decryptedKey := string(pem.EncodeToMemory(decblk))
	if decryptedKey != pkcs8Key {
		t.Fatalf("#6 got:%#v want:%#v", decryptedKey, pkcs8Key)
	}
}

const mypassword = "foobar"

const pkcs8KeyWithPassword = `-----BEGIN ENCRYPTED PRIVATE KEY-----
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
K5vUkelNr8kY4z7dpiU3WM60AA==
-----END ENCRYPTED PRIVATE KEY-----
`

const pkcs8Key = `-----BEGIN PRIVATE KEY-----
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
0b3NOlSALfZrqcWFmD1/QPgEvjuW
-----END PRIVATE KEY-----
`

func TestEncrypt(t *testing.T) {
	for i, data := range testData {
		t.Logf("test %v. %v", i, data.kind)
		plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
		if err != nil {
			t.Fatal("cannot decode test DER data: ", err)
		}
		password := []byte("kremvax1")
		block, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, data.kind)
		if err != nil {
			t.Error("encrypt: ", err)
			continue
		}
		if !IsEncryptedPEMBlock(block) {
			t.Error("PEM block does not appear to be encrypted")
		}
		if block.Type != "RSA PRIVATE KEY" {
			t.Errorf("unexpected block type; got %q want %q", block.Type, "RSA PRIVATE KEY")
		}
		if block.Headers["Proc-Type"] != "4,ENCRYPTED" {
			t.Errorf("block does not have correct Proc-Type header")
		}
		der, err := DecryptPEMBlock(block, password)
		if err != nil {
			t.Error("decrypt: ", err)
			continue
		}
		if !bytes.Equal(der, plainDER) {
			t.Errorf("data mismatch")
		}
	}
}

var testData = []struct {
	kind     PEMCipher
	password []byte
	pemData  []byte
	plainDER string
}{
	{
		kind:     PEMCipherDES,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,34F09A4FC8DE22B5

WXxy8kbZdiZvANtKvhmPBLV7eVFj2A5z6oAxvI9KGyhG0ZK0skfnt00C24vfU7m5
ICXeoqP67lzJ18xCzQfHjDaBNs53DSDT+Iz4e8QUep1xQ30+8QKX2NA2coee3nwc
6oM1cuvhNUDemBH2i3dKgMVkfaga0zQiiOq6HJyGSncCMSruQ7F9iWEfRbFcxFCx
qtHb1kirfGKEtgWTF+ynyco6+2gMXNu70L7nJcnxnV/RLFkHt7AUU1yrclxz7eZz
XOH9VfTjb52q/I8Suozq9coVQwg4tXfIoYUdT//O+mB7zJb9HI9Ps77b9TxDE6Gm
4C9brwZ3zg2vqXcwwV6QRZMtyll9rOpxkbw6NPlpfBqkc3xS51bbxivbO/Nve4KD
r12ymjFNF4stXCfJnNqKoZ50BHmEEUDu5Wb0fpVn82XrGw7CYc4iug==
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBPAIBAAJBAPASZe+tCPU6p80AjHhDkVsLYa51D35e/YGa8QcZyooeZM8EHozo
KD0fNiKI+53bHdy07N+81VQ8/ejPcRoXPlsCAwEAAQJBAMTxIuSq27VpR+zZ7WJf
c6fvv1OBvpMZ0/d1pxL/KnOAgq2rD5hDtk9b0LGhTPgQAmrrMTKuSeGoIuYE+gKQ
QvkCIQD+GC1m+/do+QRurr0uo46Kx1LzLeSCrjBk34wiOp2+dwIhAPHfTLRXS2fv
7rljm0bYa4+eDZpz+E8RcXEgzhhvcQQ9AiAI5eHZJGOyml3MXnQjiPi55WcDOw0w
glcRgT6QCEtz2wIhANSyqaFtosIkHKqrDUGfz/bb5tqMYTAnBruVPaf/WEOBAiEA
9xORWeRG1tRpso4+dYy4KdDkuLPIO01KY6neYGm3BCM=`,
	},
	{
		kind:     PEMCipher3DES,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,C1F4A6A03682C2C7

0JqVdBEH6iqM7drTkj+e2W/bE3LqakaiWhb9WUVonFkhyu8ca/QzebY3b5gCvAZQ
YwBvDcT/GHospKqPx+cxDHJNsUASDZws6bz8ZXWJGwZGExKzr0+Qx5fgXn44Ms3x
8g1ENFuTXtxo+KoNK0zuAMAqp66Llcds3Fjl4XR18QaD0CrVNAfOdgATWZm5GJxk
Fgx5f84nT+/ovvreG+xeOzWgvtKo0UUZVrhGOgfKLpa57adumcJ6SkUuBtEFpZFB
ldw5w7WC7d13x2LsRkwo8ZrDKgIV+Y9GNvhuCCkTzNP0V3gNeJpd201HZHR+9n3w
3z0VjR/MGqsfcy1ziEWMNOO53At3zlG6zP05aHMnMcZoVXadEK6L1gz++inSSDCq
gI0UJP4e3JVB7AkgYymYAwiYALAkoEIuanxoc50njJk=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOwIBAAJBANOCXKdoNS/iP/MAbl9cf1/SF3P+Ns7ZeNL27CfmDh0O6Zduaax5
NBiumd2PmjkaCu7lQ5JOibHfWn+xJsc3kw0CAwEAAQJANX/W8d1Q/sCqzkuAn4xl
B5a7qfJWaLHndu1QRLNTRJPn0Ee7OKJ4H0QKOhQM6vpjRrz+P2u9thn6wUxoPsef
QQIhAP/jCkfejFcy4v15beqKzwz08/tslVjF+Yq41eJGejmxAiEA05pMoqfkyjcx
fyvGhpoOyoCp71vSGUfR2I9CR65oKh0CIC1Msjs66LlfJtQctRq6bCEtFCxEcsP+
eEjYo/Sk6WphAiEAxpgWPMJeU/shFT28gS+tmhjPZLpEoT1qkVlC14u0b3ECIQDX
tZZZxCtPAm7shftEib0VU77Lk8MsXJcx2C4voRsjEw==`,
	},
	{
		kind:     PEMCipherAES128,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D4492E793FC835CC038A728ED174F78A

EyfQSzXSjv6BaNH+NHdXRlkHdimpF9izWlugVJAPApgXrq5YldPe2aGIOFXyJ+QE
ZIG20DYqaPzJRjTEbPNZ6Es0S2JJ5yCpKxwJuDkgJZKtF39Q2i36JeGbSZQIuWJE
GZbBpf1jDH/pr0iGonuAdl2PCCZUiy+8eLsD2tyviHUkFLOB+ykYoJ5t8ngZ/B6D
33U43LLb7+9zD4y3Q9OVHqBFGyHcxCY9+9Qh4ZnFp7DTf6RY5TNEvE3s4g6aDpBs
3NbvRVvYTgs8K9EPk4K+5R+P2kD8J8KvEIGxVa1vz8QoCJ/jr7Ka2rvNgPCex5/E
080LzLHPCrXKdlr/f50yhNWq08ZxMWQFkui+FDHPDUaEELKAXV8/5PDxw80Rtybo
AVYoCVIbZXZCuCO81op8UcOgEpTtyU5Lgh3Mw5scQL0=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOgIBAAJBAMBlj5FxYtqbcy8wY89d/S7n0+r5MzD9F63BA/Lpl78vQKtdJ5dT
cDGh/rBt1ufRrNp0WihcmZi7Mpl/3jHjiWECAwEAAQJABNOHYnKhtDIqFYj1OAJ3
k3GlU0OlERmIOoeY/cL2V4lgwllPBEs7r134AY4wMmZSBUj8UR/O4SNO668ElKPE
cQIhAOuqY7/115x5KCdGDMWi+jNaMxIvI4ETGwV40ykGzqlzAiEA0P9oEC3m9tHB
kbpjSTxaNkrXxDgdEOZz8X0uOUUwHNsCIAwzcSCiGLyYJTULUmP1ESERfW1mlV78
XzzESaJpIM/zAiBQkSTcl9VhcJreQqvjn5BnPZLP4ZHS4gPwJAGdsj5J4QIhAOVR
B3WlRNTXR2WsJ5JdByezg9xzdXzULqmga0OE339a`,
	},
	{
		kind:     PEMCipherAES192,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,E2C9FB02BCA23ADE1829F8D8BC5F5369

cqVslvHqDDM6qwU6YjezCRifXmKsrgEev7ng6Qs7UmDJOpHDgJQZI9fwMFUhIyn5
FbCu1SHkLMW52Ld3CuEqMnzWMlhPrW8tFvUOrMWPYSisv7nNq88HobZEJcUNL2MM
Y15XmHW6IJwPqhKyLHpWXyOCVEh4ODND2nV15PCoi18oTa475baxSk7+1qH7GuIs
Rb7tshNTMqHbCpyo9Rn3UxeFIf9efdl8YLiMoIqc7J8E5e9VlbeQSdLMQOgDAQJG
ReUtTw8exmKsY4gsSjhkg5uiw7/ZB1Ihto0qnfQJgjGc680qGkT1d6JfvOfeYAk6
xn5RqS/h8rYAYm64KnepfC9vIujo4NqpaREDmaLdX5MJPQ+SlytITQvgUsUq3q/t
Ss85xjQEZH3hzwjQqdJvmA4hYP6SUjxYpBM+02xZ1Xw=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOwIBAAJBAMGcRrZiNNmtF20zyS6MQ7pdGx17aFDl+lTl+qnLuJRUCMUG05xs
OmxmL/O1Qlf+bnqR8Bgg65SfKg21SYuLhiMCAwEAAQJBAL94uuHyO4wux2VC+qpj
IzPykjdU7XRcDHbbvksf4xokSeUFjjD3PB0Qa83M94y89ZfdILIqS9x5EgSB4/lX
qNkCIQD6cCIqLfzq/lYbZbQgAAjpBXeQVYsbvVtJrPrXJAlVVQIhAMXpDKMeFPMn
J0g2rbx1gngx0qOa5r5iMU5w/noN4W2XAiBjf+WzCG5yFvazD+dOx3TC0A8+4x3P
uZ3pWbaXf5PNuQIgAcdXarvhelH2w2piY1g3BPeFqhzBSCK/yLGxR82KIh8CIQDD
+qGKsd09NhQ/G27y/DARzOYtml1NvdmCQAgsDIIOLA==`,
	},
	{
		kind:     PEMCipherAES256,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8E7ED5CD731902CE938957A886A5FFBD

4Mxr+KIzRVwoOP0wwq6caSkvW0iS+GE2h2Ov/u+n9ZTMwL83PRnmjfjzBgfRZLVf
JFPXxUK26kMNpIdssNnqGOds+DhB+oSrsNKoxgxSl5OBoYv9eJTVYm7qOyAFIsjr
DRKAcjYCmzfesr7PVTowwy0RtHmYwyXMGDlAzzZrEvaiySFFmMyKKvtoavwaFoc7
Pz3RZScwIuubzTGJ1x8EzdffYOsdCa9Mtgpp3L136+23dOd6L/qK2EG2fzrJSHs/
2XugkleBFSMKzEp9mxXKRfa++uidQvMZTFLDK9w5YjrRvMBo/l2BoZIsq0jAIE1N
sv5Z/KwlX+3MDEpPQpUwGPlGGdLnjI3UZ+cjgqBcoMiNc6HfgbBgYJSU6aDSHuCk
clCwByxWkBNgJ2GrkwNrF26v+bGJJJNR4SKouY1jQf0=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOgIBAAJBAKy3GFkstoCHIEeUU/qO8207m8WSrjksR+p9B4tf1w5k+2O1V/GY
AQ5WFCApItcOkQe/I0yZZJk/PmCqMzSxrc8CAwEAAQJAOCAz0F7AW9oNelVQSP8F
Sfzx7O1yom+qWyAQQJF/gFR11gpf9xpVnnyu1WxIRnDUh1LZwUsjwlDYb7MB74id
oQIhANPcOiLwOPT4sIUpRM5HG6BF1BI7L77VpyGVk8xNP7X/AiEA0LMHZtk4I+lJ
nClgYp4Yh2JZ1Znbu7IoQMCEJCjwKDECIGd8Dzm5tViTkUW6Hs3Tlf73nNs65duF
aRnSglss8I3pAiEAonEnKruawgD8RavDFR+fUgmQiPz4FnGGeVgfwpGG1JECIBYq
PXHYtPqxQIbD2pScR5qum7iGUh11lEUPkmt+2uqS`,
	},
	{
		// generated with:
		// openssl genrsa -aes128 -passout pass:asdf -out server.orig.key 128
		kind:     PEMCipherAES128,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6ei/MlytjE0FFgZOGQ+jrwomKfpl8kdefeE0NSt/DMRrw8OacHAzBNi3pPEa0eX3
eND9l7C9meCirWovjj9QWVHrXyugFuDIqgdhQ8iHTgCfF3lrmcttVrbIfMDw+smD
hTP8O1mS/MHl92NE0nhv0w==
-----END RSA TESTING KEY-----`)),
		plainDER: `
MGMCAQACEQC6ssxmYuauuHGOCDAI54RdAgMBAAECEQCWIn6Yv2O+kBcDF7STctKB
AgkA8SEfu/2i3g0CCQDGNlXbBHX7kQIIK3Ww5o0cYbECCQDCimPb0dYGsQIIeQ7A
jryIst8=`,
	},
}

var incompleteBlockPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6L8yXK2MTQUWBk4ZD6OvCiYp+mXyR1594TQ1K38MxGvDw5pwcDME2Lek8RrR5fd40P2XsL2Z4KKt
ai+OP1BZUetfK6AW4MiqB2FDyIdOAJ8XeWuZy21Wtsh8wPD6yYOFM/w7WZL8weX3Y0TSeG/T
-----END RSA TESTING KEY-----`)

func TestIncompleteBlock(t *testing.T) {
	// incompleteBlockPEM contains ciphertext that is not a multiple of the
	// block size. This previously panicked. See #11215.
	block, _ := pem.Decode([]byte(incompleteBlockPEM))
	_, err := DecryptPEMBlock(block, []byte("foo"))
	if err == nil {
		t.Fatal("Bad PEM data decrypted successfully")
	}
	const expectedSubstr = "block size"
	if e := err.Error(); !strings.Contains(e, expectedSubstr) {
		t.Fatalf("Expected error containing %q but got: %q", expectedSubstr, e)
	}
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
