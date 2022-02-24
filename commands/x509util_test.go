package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// 4096-bit RSA private key
const testTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testTokenPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}
func TestEncode(t *testing.T) {
	rsaPrivateKey := loadPrivateKey(t)
	publicKey := rsaPrivateKey.PublicKey

	publicKeyEnc, err := marshalTokenKey(&publicKey, false)
	if err != nil {
		t.Fatal(err)
	}

	recoveredKey, err := unmarshalTokenKey(publicKeyEnc)
	if err != nil {
		t.Fatal(err)
	}

	legacyEnc, err := marshalTokenKey(&publicKey, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(legacyEnc))

	if publicKey.N.Cmp(recoveredKey.N) != 0 {
		t.Fatal("N mismatch")
	}
	if publicKey.E != recoveredKey.E {
		t.Fatal("E mismatch")
	}
}
