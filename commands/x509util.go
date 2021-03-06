package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PSSPublicKey struct {
	N *big.Int
	E int
}

var (
	oidPublicKeyRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidPKCS1MGF        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

func marshalTokenKeyPSSOID(key *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := asn1.Marshal(pkcs1PSSPublicKey{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPublicKeyRSAPSS)
			b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidSHA384)
					})
				})
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidPKCS1MGF)
						b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(oidSHA384)
						})
					})
				})
				b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1Int64(48)
				})
			})
		})
		b.AddASN1BitString(publicKeyBytes)
	})

	return b.BytesOrPanic(), nil
}

func marshalTokenKeyRSAEncryptionOID(key *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func marshalTokenKey(key *rsa.PublicKey, legacyFormat bool) ([]byte, error) {
	if legacyFormat {
		return marshalTokenKeyRSAEncryptionOID(key)
	} else {
		return marshalTokenKeyPSSOID(key)
	}
}

func unmarshalTokenKey(data []byte) (*rsa.PublicKey, error) {
	s := cryptobyte.String(data)

	var sequenceString cryptobyte.String
	if !s.ReadASN1(&sequenceString, cryptobyte_asn1.SEQUENCE.Constructed()) {
		return nil, fmt.Errorf("Invalid SPKI token key encoding (failed reading outer sequence)")
	}

	var paramsString cryptobyte.String
	if !sequenceString.ReadASN1(&paramsString, cryptobyte_asn1.SEQUENCE.Constructed()) {
		return nil, fmt.Errorf("Invalid SPKI token key encoding (failed reading parameters)")
	}

	var publicKeyString asn1.BitString
	if !sequenceString.ReadASN1BitString(&publicKeyString) {
		return nil, fmt.Errorf("Invalid SPKI token key encoding (failed reading public key)")
	}

	der := cryptobyte.String(publicKeyString.RightAlign())
	p := &pkcs1PSSPublicKey{N: new(big.Int)}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid RSA public key")
	}
	if !der.ReadASN1Integer(p.N) {
		return nil, errors.New("x509: invalid RSA modulus")
	}
	if !der.ReadASN1Integer(&p.E) {
		return nil, errors.New("x509: invalid RSA public exponent")
	}

	key := new(rsa.PublicKey) // Everything else is uninitialized
	key.N = p.N
	key.E = p.E

	return key, nil
}
